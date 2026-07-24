use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::{VaultError, VaultResult};
use crate::types::{SecretBytes, VaultItem};

const VAULT_KEY_LEN: usize = 32;
const XNONCE_LEN: usize = 24;
const ITEM_RECORD_FORMAT: &str = "psw-local-vault-item-record";

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

fn record_aad(record: &EncryptedItemRecord) -> Vec<u8> {
    format!(
        "{}:{}:{}:{}",
        record.format, record.version, record.item_id, record.revision
    )
    .into_bytes()
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
    use crate::record::{decrypt_item_record, encrypt_item_record};
    use crate::{
        ItemId, ItemRevision, ItemStatus, LoginItem, SecretBytes, VaultItem, VaultItemContent,
        VaultItemDraft,
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
