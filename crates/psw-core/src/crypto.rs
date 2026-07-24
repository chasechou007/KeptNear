use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::{VaultError, VaultResult};
use crate::types::SecretBytes;

const VAULT_KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const XNONCE_LEN: usize = 24;
const KEY_AAD: &[u8] = b"psw-local-vault:key-envelope:v1";
const LOCAL_UNLOCK_AAD: &[u8] = b"psw-local-vault:local-unlock-envelope:v1";

/// Length in bytes for random local convenience unlock material.
pub const LOCAL_UNLOCK_KEY_LEN: usize = VAULT_KEY_LEN;

/// Serialized key envelope stored in `keys.enc`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyEnvelope {
    /// Envelope format name.
    pub format: String,
    /// Envelope version.
    pub version: u32,
    /// KDF metadata.
    pub kdf: KdfMetadata,
    /// AEAD algorithm.
    pub aead: String,
    /// Hex-encoded nonce.
    pub nonce_hex: String,
    /// Hex-encoded encrypted vault key.
    pub ciphertext_hex: String,
}

/// Argon2id metadata for the key envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KdfMetadata {
    /// KDF algorithm name.
    pub algorithm: String,
    /// Argon2 version.
    pub version: u32,
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Iteration count.
    pub iterations: u32,
    /// Parallelism lanes.
    pub parallelism: u32,
    /// Hex-encoded salt.
    pub salt_hex: String,
}

/// Serialized local unlock envelope stored beside vault files.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocalUnlockEnvelope {
    /// Envelope format name.
    pub format: String,
    /// Envelope version.
    pub version: u32,
    /// AEAD algorithm.
    pub aead: String,
    /// Hex-encoded nonce.
    pub nonce_hex: String,
    /// Hex-encoded encrypted vault key.
    pub ciphertext_hex: String,
}

impl KdfMetadata {
    fn current(salt: &[u8]) -> Self {
        Self {
            algorithm: "argon2id".to_owned(),
            version: 0x13,
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
            salt_hex: hex::encode(salt),
        }
    }
}

/// Creates a new encrypted key envelope for a random vault key.
pub fn create_key_envelope(master_password: &SecretBytes) -> VaultResult<KeyEnvelope> {
    validate_master_password_policy(master_password)?;

    let mut vault_key = [0_u8; VAULT_KEY_LEN];
    OsRng.fill_bytes(&mut vault_key);

    let envelope = wrap_vault_key(master_password, &vault_key)?;

    vault_key.fill(0);

    Ok(envelope)
}

/// Decrypts the vault key from an encrypted key envelope.
pub fn decrypt_key_envelope(
    envelope: &KeyEnvelope,
    master_password: &SecretBytes,
) -> VaultResult<SecretBytes> {
    if envelope.format != "psw-local-vault-key-envelope" || envelope.version != 1 {
        return Err(VaultError::InvalidVault {
            reason: "unsupported key envelope".to_owned(),
        });
    }
    if envelope.aead != "xchacha20poly1305" {
        return Err(VaultError::InvalidVault {
            reason: "unsupported key envelope AEAD".to_owned(),
        });
    }

    let nonce = decode_fixed_hex::<XNONCE_LEN>(&envelope.nonce_hex, "decode key nonce")?;
    let ciphertext = hex::decode(&envelope.ciphertext_hex).map_err(|error| VaultError::Crypto {
        operation: "decode key ciphertext",
        reason: error.to_string(),
    })?;
    let wrapping_key = derive_wrapping_key(master_password.expose(), &envelope.kdf)?;
    let vault_key = decrypt_with_key(&wrapping_key, &nonce, &ciphertext, KEY_AAD)?;

    Ok(SecretBytes::new(vault_key))
}

/// Rewraps an existing key envelope with a new master password.
pub fn rewrap_key_envelope(
    envelope: &KeyEnvelope,
    current_master_password: &SecretBytes,
    new_master_password: &SecretBytes,
) -> VaultResult<KeyEnvelope> {
    validate_master_password_policy(new_master_password)?;

    let vault_key = decrypt_key_envelope(envelope, current_master_password)?;
    wrap_vault_key(new_master_password, fixed_vault_key(&vault_key)?)
}

/// Validates master password material for new key-envelope writes.
pub fn validate_master_password_policy(master_password: &SecretBytes) -> VaultResult<()> {
    if master_password.expose().is_empty() {
        return Err(VaultError::InvalidVault {
            reason: "master password is required".to_owned(),
        });
    }
    Ok(())
}

/// Creates a local unlock envelope and returns the random local unlock key.
pub fn create_local_unlock_envelope(
    vault_key: &SecretBytes,
) -> VaultResult<(SecretBytes, LocalUnlockEnvelope)> {
    let mut local_unlock_key = [0_u8; LOCAL_UNLOCK_KEY_LEN];
    let mut nonce = [0_u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut local_unlock_key);
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = encrypt_with_key(
        &local_unlock_key,
        &nonce,
        fixed_vault_key(vault_key)?,
        LOCAL_UNLOCK_AAD,
        "encrypt local unlock envelope",
    )?;
    let material = SecretBytes::new(local_unlock_key.to_vec());
    local_unlock_key.fill(0);

    Ok((
        material,
        LocalUnlockEnvelope {
            format: "psw-local-unlock-envelope".to_owned(),
            version: 1,
            aead: "xchacha20poly1305".to_owned(),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(ciphertext),
        },
    ))
}

/// Decrypts a vault key from a local unlock envelope.
pub fn decrypt_local_unlock_envelope(
    envelope: &LocalUnlockEnvelope,
    local_unlock_key: &SecretBytes,
) -> VaultResult<SecretBytes> {
    if envelope.format != "psw-local-unlock-envelope" || envelope.version != 1 {
        return Err(VaultError::InvalidVault {
            reason: "unsupported local unlock envelope".to_owned(),
        });
    }
    if envelope.aead != "xchacha20poly1305" {
        return Err(VaultError::InvalidVault {
            reason: "unsupported local unlock envelope AEAD".to_owned(),
        });
    }
    let key = fixed_local_unlock_key(local_unlock_key)?;
    let nonce = decode_fixed_hex::<XNONCE_LEN>(&envelope.nonce_hex, "decode local unlock nonce")?;
    let ciphertext = hex::decode(&envelope.ciphertext_hex).map_err(|error| VaultError::Crypto {
        operation: "decode local unlock ciphertext",
        reason: error.to_string(),
    })?;
    let vault_key = decrypt_with_key(key, &nonce, &ciphertext, LOCAL_UNLOCK_AAD)?;

    Ok(SecretBytes::new(vault_key))
}

fn wrap_vault_key(
    master_password: &SecretBytes,
    vault_key: &[u8; VAULT_KEY_LEN],
) -> VaultResult<KeyEnvelope> {
    let mut salt = [0_u8; SALT_LEN];
    let mut nonce = [0_u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let kdf = KdfMetadata::current(&salt);
    let wrapping_key = derive_wrapping_key(master_password.expose(), &kdf)?;
    let ciphertext = encrypt_with_key(
        &wrapping_key,
        &nonce,
        vault_key,
        KEY_AAD,
        "encrypt vault key",
    )?;

    Ok(KeyEnvelope {
        format: "psw-local-vault-key-envelope".to_owned(),
        version: 1,
        kdf,
        aead: "xchacha20poly1305".to_owned(),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

fn fixed_vault_key(secret: &SecretBytes) -> VaultResult<&[u8; VAULT_KEY_LEN]> {
    secret
        .expose()
        .try_into()
        .map_err(|_| VaultError::InvalidVault {
            reason: "vault key has invalid length".to_owned(),
        })
}

fn fixed_local_unlock_key(secret: &SecretBytes) -> VaultResult<&[u8; LOCAL_UNLOCK_KEY_LEN]> {
    secret
        .expose()
        .try_into()
        .map_err(|_| VaultError::InvalidVault {
            reason: "local unlock material has invalid length".to_owned(),
        })
}

fn derive_wrapping_key(
    password: &[u8],
    metadata: &KdfMetadata,
) -> VaultResult<[u8; VAULT_KEY_LEN]> {
    if metadata.algorithm != "argon2id" || metadata.version != 0x13 {
        return Err(VaultError::InvalidVault {
            reason: "unsupported key derivation metadata".to_owned(),
        });
    }

    let salt = hex::decode(&metadata.salt_hex).map_err(|error| VaultError::Crypto {
        operation: "decode key salt",
        reason: error.to_string(),
    })?;
    let params = Params::new(
        metadata.memory_kib,
        metadata.iterations,
        metadata.parallelism,
        Some(VAULT_KEY_LEN),
    )
    .map_err(|error| VaultError::Crypto {
        operation: "create argon2 parameters",
        reason: error.to_string(),
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0_u8; VAULT_KEY_LEN];
    argon2
        .hash_password_into(password, &salt, &mut output)
        .map_err(|error| VaultError::Crypto {
            operation: "derive wrapping key",
            reason: error.to_string(),
        })?;
    Ok(output)
}

fn encrypt_with_key(
    wrapping_key: &[u8; VAULT_KEY_LEN],
    nonce: &[u8; XNONCE_LEN],
    vault_key: &[u8; VAULT_KEY_LEN],
    aad: &[u8],
    operation: &'static str,
) -> VaultResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(wrapping_key.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: vault_key,
                aad,
            },
        )
        .map_err(|error| VaultError::Crypto {
            operation,
            reason: error.to_string(),
        })
}

fn decrypt_with_key(
    wrapping_key: &[u8; VAULT_KEY_LEN],
    nonce: &[u8; XNONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> VaultResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(wrapping_key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::InvalidCredentials)
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
    use crate::crypto::{
        create_key_envelope, create_local_unlock_envelope, decrypt_key_envelope,
        decrypt_local_unlock_envelope, rewrap_key_envelope,
    };
    use crate::SecretBytes;

    #[test]
    fn key_envelope_round_trips_with_correct_password() {
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let envelope = create_key_envelope(&password).expect("create envelope");

        let vault_key = decrypt_key_envelope(&envelope, &password).expect("decrypt envelope");

        assert_eq!(vault_key.expose().len(), 32);
    }

    #[test]
    fn key_envelope_accepts_short_non_empty_master_password() {
        let password = SecretBytes::new(b"short".to_vec());

        let envelope = create_key_envelope(&password).expect("create envelope");
        let vault_key = decrypt_key_envelope(&envelope, &password).expect("decrypt envelope");

        assert_eq!(vault_key.expose().len(), 32);
    }

    #[test]
    fn key_envelope_rejects_empty_master_password() {
        let password = SecretBytes::new(Vec::new());

        let error = create_key_envelope(&password).expect_err("empty password rejected");

        assert!(matches!(error, crate::VaultError::InvalidVault { .. }));
    }

    #[test]
    fn key_envelope_rejects_wrong_password() {
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let wrong_password = SecretBytes::new(b"wrong password".to_vec());
        let envelope = create_key_envelope(&password).expect("create envelope");

        let error = decrypt_key_envelope(&envelope, &wrong_password).expect_err("wrong password");

        assert!(matches!(error, crate::VaultError::InvalidCredentials));
    }

    #[test]
    fn key_envelope_rewrap_preserves_vault_key_for_new_password() {
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let new_password = SecretBytes::new(b"new correct horse battery staple".to_vec());
        let envelope = create_key_envelope(&password).expect("create envelope");
        let vault_key = decrypt_key_envelope(&envelope, &password).expect("decrypt original");

        let rewrapped =
            rewrap_key_envelope(&envelope, &password, &new_password).expect("rewrap envelope");

        let reopened = decrypt_key_envelope(&rewrapped, &new_password).expect("decrypt rewrapped");
        assert_eq!(vault_key.expose(), reopened.expose());
        assert!(matches!(
            decrypt_key_envelope(&rewrapped, &password).expect_err("old password rejected"),
            crate::VaultError::InvalidCredentials
        ));
    }

    #[test]
    fn key_envelope_rewrap_accepts_short_non_empty_new_password() {
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let short_password = SecretBytes::new(b"short".to_vec());
        let envelope = create_key_envelope(&password).expect("create envelope");
        let vault_key = decrypt_key_envelope(&envelope, &password).expect("decrypt original");

        let rewrapped =
            rewrap_key_envelope(&envelope, &password, &short_password).expect("rewrap envelope");

        let reopened =
            decrypt_key_envelope(&rewrapped, &short_password).expect("short new password works");
        assert_eq!(vault_key.expose(), reopened.expose());
    }

    #[test]
    fn local_unlock_envelope_round_trips_with_local_key() {
        let vault_key = SecretBytes::new(vec![9; 32]);
        let (local_key, envelope) =
            create_local_unlock_envelope(&vault_key).expect("create local envelope");

        let reopened =
            decrypt_local_unlock_envelope(&envelope, &local_key).expect("decrypt local envelope");

        assert_eq!(local_key.expose().len(), 32);
        assert_ne!(local_key.expose(), vault_key.expose());
        assert_eq!(reopened.expose(), vault_key.expose());
    }

    #[test]
    fn local_unlock_envelope_rejects_wrong_local_key() {
        let vault_key = SecretBytes::new(vec![9; 32]);
        let (_, envelope) =
            create_local_unlock_envelope(&vault_key).expect("create local envelope");

        let error = decrypt_local_unlock_envelope(&envelope, &SecretBytes::new(vec![8; 32]))
            .expect_err("wrong local key");

        assert!(matches!(error, crate::VaultError::InvalidCredentials));
    }
}
