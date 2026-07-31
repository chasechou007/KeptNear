use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::{VaultError, VaultResult};
use crate::revision::{CredentialRevision, CredentialRevisionError};
use crate::stable_id::{CredentialId, RevisionId, VaultId};
use crate::types::{SecretBytes, VaultItem, TARGET_RECORD_FORMAT_VERSION};

const VAULT_KEY_LEN: usize = 32;
const XNONCE_LEN: usize = 24;
const AEAD_TAG_LEN: usize = 16;
const ITEM_RECORD_FORMAT: &str = "psw-local-vault-item-record";
const TARGET_RECORD_AAD_DOMAIN: &[u8] = b"KeptNear credential revision record v2";

/// Encrypted item record persisted inside the vault `items` directory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct EncryptedItemRecord {
    /// Record format marker.
    pub format: String,
    /// Record format version.
    pub version: u32,
    /// Opaque item identifier.
    pub item_id: String,
    /// Opaque item revision identifier.
    pub revision: String,
    /// Hex-encoded XChaCha20 nonce.
    pub nonce_hex: String,
    /// Hex-encoded encrypted serialized item.
    pub ciphertext_hex: String,
}

/// Current encrypted credential record introduced by the v1-to-v2 migration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetEncryptedCredentialRecord {
    /// Record format marker.
    pub format: String,
    /// Target record format version.
    pub version: u32,
    /// Authenticated stable vault identity.
    pub vault_id: VaultId,
    /// Authenticated stable credential identity.
    pub credential_id: CredentialId,
    /// Authenticated immutable revision identity.
    pub revision_id: RevisionId,
    /// Hex-encoded XChaCha20 nonce.
    pub nonce_hex: String,
    /// Hex-encoded authenticated encrypted credential revision.
    pub ciphertext_hex: String,
}

/// Parses and validates the outer target record without decrypting its contents.
pub(crate) fn parse_target_credential_record(
    encoded: &[u8],
) -> VaultResult<TargetEncryptedCredentialRecord> {
    let record = serde_json::from_slice(encoded).map_err(|_| VaultError::InvalidVault {
        reason: "malformed target credential record".to_owned(),
    })?;
    validate_target_record_header(&record)?;
    Ok(record)
}

/// Encrypts a target credential revision with identity and ancestry in AEAD associated data.
pub(crate) fn encrypt_target_credential_record(
    vault_key: &SecretBytes,
    revision: &CredentialRevision,
) -> VaultResult<TargetEncryptedCredentialRecord> {
    revision.validate().map_err(invalid_credential_revision)?;

    let mut nonce = [0_u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let credential = revision.credential();
    let record = TargetEncryptedCredentialRecord {
        format: ITEM_RECORD_FORMAT.to_owned(),
        version: TARGET_RECORD_FORMAT_VERSION,
        vault_id: credential.vault_id(),
        credential_id: credential.credential_id(),
        revision_id: revision.revision_id(),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: String::new(),
    };
    let mut plaintext = serde_json::to_vec(revision).map_err(|error| VaultError::InvalidVault {
        reason: format!("serialize target credential revision failed: {error}"),
    })?;
    let encrypted = item_cipher(vault_key)?.encrypt(
        XNonce::from_slice(&nonce),
        Payload {
            msg: &plaintext,
            aad: &target_record_aad(&record),
        },
    );
    plaintext.fill(0);
    let ciphertext = encrypted.map_err(|error| VaultError::Crypto {
        operation: "encrypt target credential record",
        reason: error.to_string(),
    })?;

    Ok(TargetEncryptedCredentialRecord {
        ciphertext_hex: hex::encode(ciphertext),
        ..record
    })
}

/// Decrypts a target revision and verifies header and encrypted metadata agree.
pub(crate) fn decrypt_target_credential_record(
    vault_key: &SecretBytes,
    record: &TargetEncryptedCredentialRecord,
) -> VaultResult<CredentialRevision> {
    validate_target_record_header(record)?;
    let nonce = decode_fixed_hex::<XNONCE_LEN>(&record.nonce_hex, "decode target item nonce")?;
    let ciphertext = hex::decode(&record.ciphertext_hex).map_err(|error| VaultError::Crypto {
        operation: "decode target item ciphertext",
        reason: error.to_string(),
    })?;
    let mut plaintext = item_cipher(vault_key)?
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &target_record_aad(record),
            },
        )
        .map_err(|_| VaultError::InvalidVault {
            reason: "target item authentication failed".to_owned(),
        })?;
    let decoded = serde_json::from_slice(&plaintext).map_err(|error| VaultError::InvalidVault {
        reason: format!("decode target credential revision failed: {error}"),
    });
    plaintext.fill(0);
    let revision: CredentialRevision = decoded?;
    let credential = revision.credential();

    if credential.vault_id() != record.vault_id
        || credential.credential_id() != record.credential_id
        || revision.revision_id() != record.revision_id
    {
        return Err(VaultError::InvalidVault {
            reason: "target credential revision metadata mismatch".to_owned(),
        });
    }
    revision.validate().map_err(invalid_credential_revision)?;
    Ok(revision)
}

/// Encrypts one decrypted item as an independent authenticated record.
pub(crate) fn encrypt_item_record(
    vault_key: &SecretBytes,
    item: &VaultItem,
) -> VaultResult<EncryptedItemRecord> {
    let mut nonce = [0_u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let mut plaintext = serde_json::to_vec(item).map_err(|error| VaultError::InvalidVault {
        reason: format!("serialize item failed: {error}"),
    })?;
    let record = EncryptedItemRecord {
        format: ITEM_RECORD_FORMAT.to_owned(),
        version: 1,
        item_id: item.id.0.clone(),
        revision: item.revision.0.clone(),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: String::new(),
    };
    let ciphertext = item_cipher(vault_key)?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &record_aad(&record),
            },
        )
        .map_err(|error| VaultError::Crypto {
            operation: "encrypt item record",
            reason: error.to_string(),
        })?;
    plaintext.fill(0);

    Ok(EncryptedItemRecord {
        ciphertext_hex: hex::encode(ciphertext),
        ..record
    })
}

/// Decrypts and authenticates one encrypted item record.
pub(crate) fn decrypt_item_record(
    vault_key: &SecretBytes,
    record: &EncryptedItemRecord,
) -> VaultResult<VaultItem> {
    validate_record_header(record)?;
    let nonce = decode_fixed_hex::<XNONCE_LEN>(&record.nonce_hex, "decode item nonce")?;
    let ciphertext = hex::decode(&record.ciphertext_hex).map_err(|error| VaultError::Crypto {
        operation: "decode item ciphertext",
        reason: error.to_string(),
    })?;
    let mut plaintext = item_cipher(vault_key)?
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &record_aad(record),
            },
        )
        .map_err(|_| VaultError::InvalidVault {
            reason: "item authentication failed".to_owned(),
        })?;
    let item: VaultItem =
        serde_json::from_slice(&plaintext).map_err(|error| VaultError::InvalidVault {
            reason: format!("decode item plaintext failed: {error}"),
        })?;
    plaintext.fill(0);

    if item.id.0 != record.item_id || item.revision.0 != record.revision {
        return Err(VaultError::InvalidVault {
            reason: "item record identity mismatch".to_owned(),
        });
    }

    Ok(item)
}

fn item_cipher(vault_key: &SecretBytes) -> VaultResult<XChaCha20Poly1305> {
    let key = vault_key.expose();
    if key.len() != VAULT_KEY_LEN {
        return Err(VaultError::Crypto {
            operation: "create item cipher",
            reason: format!("expected {VAULT_KEY_LEN} byte vault key"),
        });
    }
    XChaCha20Poly1305::new_from_slice(key).map_err(|error| VaultError::Crypto {
        operation: "create item cipher",
        reason: error.to_string(),
    })
}

fn validate_record_header(record: &EncryptedItemRecord) -> VaultResult<()> {
    if record.format != ITEM_RECORD_FORMAT || record.version != 1 {
        return Err(VaultError::InvalidVault {
            reason: "unsupported item record format".to_owned(),
        });
    }
    Ok(())
}

fn validate_target_record_header(record: &TargetEncryptedCredentialRecord) -> VaultResult<()> {
    if record.format != ITEM_RECORD_FORMAT || record.version != TARGET_RECORD_FORMAT_VERSION {
        return Err(VaultError::InvalidVault {
            reason: "unsupported target credential record format".to_owned(),
        });
    }
    if !is_canonical_lowercase_hex(&record.nonce_hex, XNONCE_LEN * 2) {
        return Err(VaultError::InvalidVault {
            reason: "invalid target credential nonce encoding".to_owned(),
        });
    }
    if record.ciphertext_hex.len() < AEAD_TAG_LEN * 2
        || !record.ciphertext_hex.len().is_multiple_of(2)
        || !record
            .ciphertext_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VaultError::InvalidVault {
            reason: "invalid target credential ciphertext encoding".to_owned(),
        });
    }
    Ok(())
}

fn is_canonical_lowercase_hex(value: &str, expected_length: usize) -> bool {
    value.len() == expected_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_credential_revision(error: CredentialRevisionError) -> VaultError {
    VaultError::InvalidVault {
        reason: error.to_string(),
    }
}

fn record_aad(record: &EncryptedItemRecord) -> Vec<u8> {
    format!(
        "{}:{}:{}:{}",
        record.format, record.version, record.item_id, record.revision
    )
    .into_bytes()
}

fn target_record_aad(record: &TargetEncryptedCredentialRecord) -> Vec<u8> {
    let mut aad = Vec::new();
    append_aad_component(&mut aad, TARGET_RECORD_AAD_DOMAIN);
    append_aad_component(&mut aad, record.format.as_bytes());
    aad.extend_from_slice(&record.version.to_be_bytes());
    aad.extend_from_slice(record.vault_id.as_bytes());
    aad.extend_from_slice(record.credential_id.as_bytes());
    aad.extend_from_slice(record.revision_id.as_bytes());
    aad
}

fn append_aad_component(aad: &mut Vec<u8>, component: &[u8]) {
    let length = u32::try_from(component.len()).expect("record AAD component length fits u32");
    aad.extend_from_slice(&length.to_be_bytes());
    aad.extend_from_slice(component);
}

fn decode_fixed_hex<const LEN: usize>(
    value: &str,
    operation: &'static str,
) -> VaultResult<[u8; LEN]> {
    let decoded = hex::decode(value).map_err(|error| VaultError::Crypto {
        operation,
        reason: error.to_string(),
    })?;
    decoded.try_into().map_err(|_| VaultError::Crypto {
        operation,
        reason: format!("expected {LEN} bytes"),
    })
}

#[cfg(test)]
mod tests {
    use crate::record::{
        decrypt_item_record, decrypt_target_credential_record, encrypt_item_record,
        encrypt_target_credential_record, parse_target_credential_record, AEAD_TAG_LEN, XNONCE_LEN,
    };
    use crate::{
        Credential, CredentialDraft, CredentialField, CredentialId, CredentialRevision, DeviceId,
        ItemId, ItemRevision, ItemStatus, LoginItem, RevisionId, SecretBytes, SecretFieldId,
        SecretFieldKind, VaultId, VaultItem, VaultItemContent, VaultItemDraft,
    };

    #[test]
    fn item_record_round_trips() {
        let key = SecretBytes::new(vec![9; 32]);
        let item = sample_item();

        let record = encrypt_item_record(&key, &item).expect("encrypt item");
        let decrypted = decrypt_item_record(&key, &record).expect("decrypt item");

        assert_eq!(decrypted, item);
    }

    #[test]
    fn item_record_rejects_tampered_ciphertext() {
        let key = SecretBytes::new(vec![9; 32]);
        let item = sample_item();
        let mut record = encrypt_item_record(&key, &item).expect("encrypt item");
        let mut ciphertext = hex::decode(&record.ciphertext_hex).expect("decode ciphertext");
        let first = ciphertext.first_mut().expect("ciphertext byte");
        *first ^= 0x01;
        record.ciphertext_hex = hex::encode(ciphertext);

        let error = decrypt_item_record(&key, &record).expect_err("tampered record");

        assert!(matches!(error, crate::VaultError::InvalidVault { .. }));
    }

    #[test]
    fn target_credential_record_round_trips_authenticated_identities() {
        let key = SecretBytes::new(vec![9; 32]);
        let revision = sample_revision();

        let record = encrypt_target_credential_record(&key, &revision).expect("encrypt credential");
        let persisted = serde_json::to_vec(&record).expect("serialize encrypted record");
        let loaded = serde_json::from_slice(&persisted).expect("deserialize encrypted record");
        let decrypted =
            decrypt_target_credential_record(&key, &loaded).expect("decrypt credential");
        let summary = decrypted.summary().expect("summarize revision");
        let credential = revision.credential();

        assert_eq!(decrypted, revision);
        assert_eq!(record.vault_id, credential.vault_id());
        assert_eq!(record.credential_id, credential.credential_id());
        assert_eq!(record.revision_id, revision.revision_id());
        assert_eq!(summary.parent_revision_ids, revision.parent_revision_ids());
        assert_eq!(summary.content_digest, revision.content_digest());
        assert_eq!(summary.device_id, revision.device_id());
        assert_eq!(summary.credential.vault_id, credential.vault_id());
        assert_eq!(summary.credential.credential_id, credential.credential_id());
        assert_eq!(
            summary.credential.secret_fields[0].secret_field_id,
            credential.draft().fields[1]
                .secret_field_id()
                .expect("secret field ID")
        );
    }

    #[test]
    fn target_record_parser_rejects_malformed_header_fields() {
        let key = SecretBytes::new(vec![9; 32]);
        let revision = sample_revision();
        let record = encrypt_target_credential_record(&key, &revision).expect("encrypt credential");
        let encoded = serde_json::to_vec(&record).expect("serialize target record");
        assert_eq!(
            parse_target_credential_record(&encoded).expect("parse target record"),
            record
        );
        let value = serde_json::to_value(&record).expect("serialize target record value");

        let mut future_version = value.clone();
        future_version["version"] = serde_json::json!(3);
        assert_target_record_rejected(future_version);

        let mut wrong_format = value.clone();
        wrong_format["format"] = serde_json::json!("other-record-format");
        assert_target_record_rejected(wrong_format);

        let mut malformed_vault_id = value.clone();
        malformed_vault_id["vault_id"] =
            serde_json::json!(record.vault_id.to_string().to_ascii_uppercase());
        assert_target_record_rejected(malformed_vault_id);

        let mut wrong_credential_id_kind = value.clone();
        wrong_credential_id_kind["credential_id"] = serde_json::json!(record.vault_id.to_string());
        assert_target_record_rejected(wrong_credential_id_kind);

        let mut malformed_revision_id = value.clone();
        malformed_revision_id["revision_id"] = serde_json::json!("revision_not-hex");
        assert_target_record_rejected(malformed_revision_id);

        let mut uppercase_nonce = value.clone();
        uppercase_nonce["nonce_hex"] = serde_json::json!("A".repeat(XNONCE_LEN * 2));
        assert_target_record_rejected(uppercase_nonce);

        let mut short_nonce = value.clone();
        short_nonce["nonce_hex"] = serde_json::json!("00");
        assert_target_record_rejected(short_nonce);

        let mut invalid_ciphertext = value.clone();
        invalid_ciphertext["ciphertext_hex"] = serde_json::json!("AA".repeat(AEAD_TAG_LEN));
        assert_target_record_rejected(invalid_ciphertext);

        let mut unknown_field = value;
        unknown_field["unexpected"] = serde_json::Value::Bool(true);
        assert_target_record_rejected(unknown_field);
    }

    #[test]
    fn target_credential_record_rejects_tampered_header_identities() {
        let key = SecretBytes::new(vec![9; 32]);
        let revision = sample_revision();
        let record = encrypt_target_credential_record(&key, &revision).expect("encrypt credential");

        let mut changed_vault = record.clone();
        changed_vault.vault_id = VaultId::generate();
        assert!(matches!(
            decrypt_target_credential_record(&key, &changed_vault),
            Err(crate::VaultError::InvalidVault { .. })
        ));

        let mut changed_credential = record.clone();
        changed_credential.credential_id = CredentialId::generate();
        assert!(matches!(
            decrypt_target_credential_record(&key, &changed_credential),
            Err(crate::VaultError::InvalidVault { .. })
        ));

        let mut changed_revision = record.clone();
        changed_revision.revision_id = RevisionId::generate();
        assert!(matches!(
            decrypt_target_credential_record(&key, &changed_revision),
            Err(crate::VaultError::InvalidVault { .. })
        ));
    }

    #[test]
    fn target_credential_record_encrypts_and_authenticates_revision_metadata() {
        let key = SecretBytes::new(vec![9; 32]);
        let parent_revision_id = RevisionId::generate();
        let revision = CredentialRevision::descendant(
            sample_credential(),
            DeviceId::generate(),
            vec![parent_revision_id],
        )
        .expect("create descendant");
        let record = encrypt_target_credential_record(&key, &revision).expect("encrypt credential");
        let serialized_record = serde_json::to_string(&record).expect("serialize record");
        let plaintext = serde_json::to_vec(&revision).expect("serialize credential revision");

        for protected_metadata in [
            parent_revision_id.to_string(),
            revision.content_digest().to_string(),
            revision.device_id().to_string(),
        ] {
            assert!(!serialized_record.contains(&protected_metadata));
            let offset = plaintext
                .windows(protected_metadata.len())
                .position(|window| window == protected_metadata.as_bytes())
                .expect("protected metadata in encrypted plaintext");
            let mut changed_record = record.clone();
            let mut ciphertext =
                hex::decode(&changed_record.ciphertext_hex).expect("decode ciphertext");
            ciphertext[offset] ^= 0x01;
            changed_record.ciphertext_hex = hex::encode(ciphertext);
            assert!(matches!(
                decrypt_target_credential_record(&key, &changed_record),
                Err(crate::VaultError::InvalidVault { .. })
            ));
        }
    }

    #[test]
    fn target_credential_record_rejects_tampered_encrypted_field_identity() {
        let key = SecretBytes::new(vec![9; 32]);
        let revision = sample_revision();
        let secret_field_id = revision.credential().draft().fields[1]
            .secret_field_id()
            .expect("secret field ID")
            .to_string();
        let plaintext = serde_json::to_vec(&revision).expect("serialize credential revision");
        let identity_offset = plaintext
            .windows(secret_field_id.len())
            .position(|window| window == secret_field_id.as_bytes())
            .expect("secret field identity in plaintext");
        let mut record =
            encrypt_target_credential_record(&key, &revision).expect("encrypt credential");
        let mut ciphertext = hex::decode(&record.ciphertext_hex).expect("decode ciphertext");
        ciphertext[identity_offset] ^= 0x01;
        record.ciphertext_hex = hex::encode(ciphertext);

        assert!(matches!(
            decrypt_target_credential_record(&key, &record),
            Err(crate::VaultError::InvalidVault { .. })
        ));
    }

    #[test]
    fn target_revision_construction_rejects_duplicate_secret_field_identities() {
        let secret_field_id = SecretFieldId::generate();
        let mut credential = Credential::new(
            VaultId::generate(),
            CredentialDraft {
                title: "Duplicate IDs".to_owned(),
                template_id: None,
                fields: vec![
                    CredentialField::secret_with_id(
                        "first",
                        secret_field_id,
                        SecretFieldKind::ApiToken,
                        SecretBytes::new(b"first".to_vec()),
                    ),
                    CredentialField::secret_with_id(
                        "second",
                        SecretFieldId::generate(),
                        SecretFieldKind::ApiKey,
                        SecretBytes::new(b"second".to_vec()),
                    ),
                ],
                tags: Vec::new(),
                favorite: false,
            },
        )
        .expect("create credential");
        let crate::CredentialFieldValue::Secret {
            secret_field_id: duplicate_id,
            ..
        } = &mut credential.draft_mut().fields[1].value
        else {
            panic!("expected secret field");
        };
        *duplicate_id = secret_field_id;

        let revision = CredentialRevision::initial(credential, DeviceId::generate())
            .expect_err("reject invalid credential before record encryption");
        assert!(revision.reason().contains("credential identities"));
    }

    fn sample_revision() -> CredentialRevision {
        CredentialRevision::initial(sample_credential(), DeviceId::generate())
            .expect("create sample revision")
    }

    fn assert_target_record_rejected(value: serde_json::Value) {
        let encoded = serde_json::to_vec(&value).expect("serialize malformed target record");
        assert!(matches!(
            parse_target_credential_record(&encoded),
            Err(crate::VaultError::InvalidVault { .. })
        ));
    }

    fn sample_credential() -> Credential {
        Credential::with_id(
            VaultId::generate(),
            CredentialId::generate(),
            CredentialDraft {
                title: "Example token".to_owned(),
                template_id: Some("api-token".to_owned()),
                fields: vec![
                    CredentialField::text("account", "alice"),
                    CredentialField::secret_with_id(
                        "token",
                        SecretFieldId::generate(),
                        SecretFieldKind::ApiToken,
                        SecretBytes::new(b"synthetic-secret".to_vec()),
                    ),
                ],
                tags: vec!["demo".to_owned()],
                favorite: true,
            },
        )
        .expect("create sample credential")
    }

    fn sample_item() -> VaultItem {
        VaultItem {
            id: ItemId("item_1".to_owned()),
            revision: ItemRevision("rev_1".to_owned()),
            parent_revision: None,
            status: ItemStatus::Active,
            draft: VaultItemDraft {
                title: "Example".to_owned(),
                content: VaultItemContent::Login(LoginItem {
                    username: Some("user".to_owned()),
                    password: Some(SecretBytes::new(b"secret".to_vec())),
                    urls: vec!["https://example.com".to_owned()],
                    notes: None,
                    totp_secret: None,
                }),
                tags: vec!["demo".to_owned()],
                favorite: true,
            },
        }
    }
}
