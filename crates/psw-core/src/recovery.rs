use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{de, Deserialize, Deserializer, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{VaultError, VaultResult};
use crate::stable_id::{RecoveryKeyId, VaultId};
use crate::types::SecretBytes;

const RECOVERY_AUTHORITY_LEN: usize = 32;
const RECOVERY_KEY_FORMAT_VERSION: u8 = 0x01;
const RECOVERY_KEY_HRP: &str = "knr";
const RECOVERY_KEY_CANONICAL_LEN: usize = 63;
const VAULT_KEY_LEN: usize = 32;
const XNONCE_LEN: usize = 24;
const POLY1305_TAG_LEN: usize = 16;
const RECOVERY_CIPHERTEXT_LEN: usize = VAULT_KEY_LEN + POLY1305_TAG_LEN;
const RECOVERY_ENVELOPE_FORMAT: &str = "keptnear-recovery-envelope";
const RECOVERY_ENVELOPE_VERSION: u32 = 1;
const RECOVERY_ENVELOPE_ROLE: &str = "vault-key-recovery";
const RECOVERY_KDF: &str = "hkdf-sha256";
const RECOVERY_AEAD: &str = "xchacha20poly1305";
const RECOVERY_HKDF_INFO: &[u8] = b"KeptNear recovery wrap key v1";
const RECOVERY_AAD_DOMAIN: &[u8] = b"KeptNear recovery envelope AAD v1";
const RECOVERY_ENVELOPE_MAX_JSON_LEN: usize = 4_096;

/// High-entropy offline authority that can recover one vault.
///
/// The authority is deliberately not serializable and its debug representation
/// is redacted. Call [`RecoveryKey::expose_canonical`] only in an explicit
/// recovery-material workflow.
pub struct RecoveryKey([u8; RECOVERY_AUTHORITY_LEN]);

impl RecoveryKey {
    /// Generates 256 bits of recovery authority using the operating-system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut authority = [0_u8; RECOVERY_AUTHORITY_LEN];
        OsRng.fill_bytes(&mut authority);
        Self(authority)
    }

    /// Encodes the authority as the canonical lowercase `knr` Bech32m value.
    ///
    /// The returned string is secret recovery material and must be zeroized by
    /// the caller after its explicit display, print, or export workflow.
    #[must_use]
    pub fn expose_canonical(&self) -> String {
        let mut payload = [0_u8; RECOVERY_AUTHORITY_LEN + 1];
        payload[0] = RECOVERY_KEY_FORMAT_VERSION;
        payload[1..].copy_from_slice(&self.0);

        let encoded = bech32::encode::<Bech32m>(recovery_hrp(), &payload)
            .expect("fixed recovery-key payload must be Bech32m encodable");
        payload.zeroize();
        encoded
    }

    fn authority(&self) -> &[u8; RECOVERY_AUTHORITY_LEN] {
        &self.0
    }
}

impl Clone for RecoveryKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Debug for RecoveryKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecoveryKey([REDACTED])")
    }
}

impl PartialEq for RecoveryKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for RecoveryKey {}

impl Drop for RecoveryKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl FromStr for RecoveryKey {
    type Err = RecoveryKeyParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_recovery_key(value)
    }
}

/// Error returned when recovery authority is malformed or non-canonical.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryKeyParseError;

impl Display for RecoveryKeyParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid KeptNear recovery key")
    }
}

impl std::error::Error for RecoveryKeyParseError {}

/// Secret-bearing recovery material prepared for explicit display or export.
///
/// This value is deliberately not serializable or cloneable. Its text buffers
/// are zeroized on drop, and its debug representation never includes recovery
/// authority.
pub struct RecoveryKit {
    vault_id: VaultId,
    recovery_key_id: RecoveryKeyId,
    generated_at_unix_seconds: u64,
    canonical_code: String,
    grouped_code: String,
    qr_payload: String,
    verification_groups: Vec<String>,
}

impl RecoveryKit {
    /// Renders one recovery authority into canonical display and QR forms.
    #[must_use]
    pub fn render(
        recovery_key: &RecoveryKey,
        vault_id: VaultId,
        recovery_key_id: RecoveryKeyId,
        generated_at_unix_seconds: u64,
    ) -> Self {
        let canonical_code = recovery_key.expose_canonical();
        let uppercase = canonical_code.to_ascii_uppercase();
        let (prefix, payload) = uppercase.split_at(RECOVERY_KEY_HRP.len() + 1);
        let payload_groups = payload
            .as_bytes()
            .chunks(4)
            .map(|chunk| {
                std::str::from_utf8(chunk)
                    .expect("canonical Bech32m recovery key is ASCII")
                    .to_owned()
            })
            .collect::<Vec<_>>();
        let grouped_code = format!("{prefix} {}", payload_groups.join(" "));
        let verification_groups = payload_groups
            .iter()
            .filter(|group| group.len() == 4)
            .cloned()
            .collect();
        let qr_payload = canonical_code.clone();

        Self {
            vault_id,
            recovery_key_id,
            generated_at_unix_seconds,
            canonical_code,
            grouped_code,
            qr_payload,
            verification_groups,
        }
    }

    /// Returns the vault identity printed in the recovery kit.
    #[must_use]
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Returns the recovery-key generation identity printed in the recovery kit.
    #[must_use]
    pub fn recovery_key_id(&self) -> RecoveryKeyId {
        self.recovery_key_id
    }

    /// Returns the caller-supplied generation time as Unix seconds.
    #[must_use]
    pub fn generated_at_unix_seconds(&self) -> u64 {
        self.generated_at_unix_seconds
    }

    /// Exposes the canonical lowercase recovery code for an explicit workflow.
    #[must_use]
    pub fn canonical_code(&self) -> &str {
        &self.canonical_code
    }

    /// Exposes the uppercase, four-character-grouped display code.
    #[must_use]
    pub fn grouped_code(&self) -> &str {
        &self.grouped_code
    }

    /// Exposes the canonical lowercase payload to encode as a QR code.
    #[must_use]
    pub fn qr_payload(&self) -> &str {
        &self.qr_payload
    }

    /// Exposes the fourteen complete numbered groups available for paper checks.
    #[must_use]
    pub fn verification_groups(&self) -> &[String] {
        &self.verification_groups
    }
}

impl Debug for RecoveryKit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryKit")
            .field("vault_id", &self.vault_id)
            .field("recovery_key_id", &self.recovery_key_id)
            .field("generated_at_unix_seconds", &self.generated_at_unix_seconds)
            .field("recovery_material", &"[REDACTED]")
            .finish()
    }
}

impl Drop for RecoveryKit {
    fn drop(&mut self) {
        self.canonical_code.zeroize();
        self.grouped_code.zeroize();
        self.qr_payload.zeroize();
        self.verification_groups.zeroize();
    }
}

/// Authenticated wrapped vault-key material stored with a portable vault.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveryEnvelope {
    format: String,
    version: u32,
    vault_id: VaultId,
    recovery_key_id: RecoveryKeyId,
    role: String,
    kdf: String,
    aead: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

impl RecoveryEnvelope {
    /// Maximum accepted serialized envelope size in bytes.
    pub const MAX_ENCODED_LEN: usize = RECOVERY_ENVELOPE_MAX_JSON_LEN;

    /// Strictly parses and validates a serialized recovery envelope.
    pub fn parse_json(encoded: &[u8]) -> VaultResult<Self> {
        if encoded.len() > RECOVERY_ENVELOPE_MAX_JSON_LEN {
            return Err(VaultError::InvalidVault {
                reason: "recovery envelope exceeds the maximum encoded size".to_owned(),
            });
        }
        serde_json::from_slice(encoded).map_err(|error| VaultError::InvalidVault {
            reason: format!("parse recovery envelope failed: {error}"),
        })
    }

    /// Serializes the validated recovery envelope as portable JSON.
    pub fn to_json(&self) -> VaultResult<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec_pretty(self).map_err(|error| VaultError::InvalidVault {
            reason: format!("serialize recovery envelope failed: {error}"),
        })
    }

    /// Returns the vault identity cryptographically bound to this envelope.
    #[must_use]
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Returns the identity of this recovery-key generation.
    #[must_use]
    pub fn recovery_key_id(&self) -> RecoveryKeyId {
        self.recovery_key_id
    }

    /// Returns this envelope's supported format version.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    fn validate(&self) -> VaultResult<()> {
        if self.format != RECOVERY_ENVELOPE_FORMAT || self.version != RECOVERY_ENVELOPE_VERSION {
            return Err(VaultError::InvalidVault {
                reason: "unsupported recovery envelope format or version".to_owned(),
            });
        }
        if self.role != RECOVERY_ENVELOPE_ROLE {
            return Err(VaultError::InvalidVault {
                reason: "unsupported recovery envelope role".to_owned(),
            });
        }
        if self.kdf != RECOVERY_KDF {
            return Err(VaultError::InvalidVault {
                reason: "unsupported recovery envelope KDF".to_owned(),
            });
        }
        if self.aead != RECOVERY_AEAD {
            return Err(VaultError::InvalidVault {
                reason: "unsupported recovery envelope AEAD".to_owned(),
            });
        }

        decode_canonical_hex::<XNONCE_LEN>(&self.nonce_hex, "recovery envelope nonce")?;
        decode_canonical_hex::<RECOVERY_CIPHERTEXT_LEN>(
            &self.ciphertext_hex,
            "recovery envelope ciphertext",
        )?;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryEnvelopeDocument {
    format: String,
    version: u32,
    vault_id: VaultId,
    recovery_key_id: RecoveryKeyId,
    role: String,
    kdf: String,
    aead: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

impl<'de> Deserialize<'de> for RecoveryEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let document = RecoveryEnvelopeDocument::deserialize(deserializer)?;
        let envelope = Self {
            format: document.format,
            version: document.version,
            vault_id: document.vault_id,
            recovery_key_id: document.recovery_key_id,
            role: document.role,
            kdf: document.kdf,
            aead: document.aead,
            nonce_hex: document.nonce_hex,
            ciphertext_hex: document.ciphertext_hex,
        };
        envelope.validate().map_err(de::Error::custom)?;
        Ok(envelope)
    }
}

/// Generates recovery authority and independently wraps an existing random vault key.
pub fn create_recovery_envelope(
    vault_id: VaultId,
    vault_key: &SecretBytes,
) -> VaultResult<(RecoveryKey, RecoveryEnvelope)> {
    let recovery_key = RecoveryKey::generate();
    let recovery_key_id = RecoveryKeyId::generate();
    let mut nonce = [0_u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let envelope =
        wrap_recovery_envelope(vault_id, recovery_key_id, vault_key, &recovery_key, &nonce)?;
    Ok((recovery_key, envelope))
}

/// Unwraps a vault key after authenticating the envelope and its expected vault identity.
pub fn decrypt_recovery_envelope(
    envelope: &RecoveryEnvelope,
    expected_vault_id: VaultId,
    recovery_key: &RecoveryKey,
) -> VaultResult<SecretBytes> {
    envelope.validate()?;
    if envelope.vault_id != expected_vault_id {
        return Err(VaultError::InvalidVault {
            reason: "recovery envelope vault identity mismatch".to_owned(),
        });
    }

    let nonce = decode_canonical_hex::<XNONCE_LEN>(&envelope.nonce_hex, "recovery envelope nonce")?;
    let ciphertext = decode_canonical_hex::<RECOVERY_CIPHERTEXT_LEN>(
        &envelope.ciphertext_hex,
        "recovery envelope ciphertext",
    )?;
    let mut wrapping_key = derive_recovery_wrapping_key(expected_vault_id, recovery_key)?;
    let aad = recovery_envelope_aad(envelope.vault_id, envelope.recovery_key_id, &nonce);
    let cipher = XChaCha20Poly1305::new((&wrapping_key).into());
    let decrypted = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::InvalidCredentials);
    wrapping_key.zeroize();

    let vault_key = decrypted?;
    if vault_key.len() != VAULT_KEY_LEN {
        return Err(VaultError::InvalidVault {
            reason: "recovery envelope contained an invalid vault key".to_owned(),
        });
    }
    Ok(SecretBytes::new(vault_key))
}

fn parse_recovery_key(value: &str) -> Result<RecoveryKey, RecoveryKeyParseError> {
    let compact_length = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .count();
    if compact_length != RECOVERY_KEY_CANONICAL_LEN {
        return Err(RecoveryKeyParseError);
    }

    let mut compact = Zeroizing::new(String::with_capacity(RECOVERY_KEY_CANONICAL_LEN));
    for character in value.chars() {
        if !character.is_ascii_whitespace() {
            compact.push(character);
        }
    }
    let has_lowercase = compact.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_uppercase = compact.bytes().any(|byte| byte.is_ascii_uppercase());
    if has_lowercase && has_uppercase {
        return Err(RecoveryKeyParseError);
    }

    let normalized = Zeroizing::new(compact.to_ascii_lowercase());
    let checked =
        CheckedHrpstring::new::<Bech32m>(&normalized).map_err(|_| RecoveryKeyParseError)?;
    if checked.hrp() != recovery_hrp() {
        return Err(RecoveryKeyParseError);
    }

    let mut payload = Zeroizing::new([0_u8; RECOVERY_AUTHORITY_LEN + 1]);
    let mut decoded = checked.byte_iter();
    for byte in payload.iter_mut() {
        *byte = decoded.next().ok_or(RecoveryKeyParseError)?;
    }
    if decoded.next().is_some() || payload[0] != RECOVERY_KEY_FORMAT_VERSION {
        return Err(RecoveryKeyParseError);
    }

    let canonical = Zeroizing::new(
        bech32::encode::<Bech32m>(recovery_hrp(), payload.as_ref())
            .map_err(|_| RecoveryKeyParseError)?,
    );
    if canonical.as_str() != normalized.as_str() {
        return Err(RecoveryKeyParseError);
    }

    let mut authority = [0_u8; RECOVERY_AUTHORITY_LEN];
    authority.copy_from_slice(&payload[1..]);
    Ok(RecoveryKey(authority))
}

fn wrap_recovery_envelope(
    vault_id: VaultId,
    recovery_key_id: RecoveryKeyId,
    vault_key: &SecretBytes,
    recovery_key: &RecoveryKey,
    nonce: &[u8; XNONCE_LEN],
) -> VaultResult<RecoveryEnvelope> {
    let vault_key: &[u8; VAULT_KEY_LEN] =
        vault_key
            .expose()
            .try_into()
            .map_err(|_| VaultError::InvalidVault {
                reason: "vault key has invalid length".to_owned(),
            })?;
    let mut wrapping_key = derive_recovery_wrapping_key(vault_id, recovery_key)?;
    let aad = recovery_envelope_aad(vault_id, recovery_key_id, nonce);
    let cipher = XChaCha20Poly1305::new((&wrapping_key).into());
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: vault_key,
                aad: &aad,
            },
        )
        .map_err(|error| VaultError::Crypto {
            operation: "encrypt recovery envelope",
            reason: error.to_string(),
        });
    wrapping_key.zeroize();
    let ciphertext = encrypted?;

    Ok(RecoveryEnvelope {
        format: RECOVERY_ENVELOPE_FORMAT.to_owned(),
        version: RECOVERY_ENVELOPE_VERSION,
        vault_id,
        recovery_key_id,
        role: RECOVERY_ENVELOPE_ROLE.to_owned(),
        kdf: RECOVERY_KDF.to_owned(),
        aead: RECOVERY_AEAD.to_owned(),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

fn derive_recovery_wrapping_key(
    vault_id: VaultId,
    recovery_key: &RecoveryKey,
) -> VaultResult<[u8; VAULT_KEY_LEN]> {
    let salt = vault_id.to_string();
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), recovery_key.authority());
    let mut wrapping_key = [0_u8; VAULT_KEY_LEN];
    hkdf.expand(RECOVERY_HKDF_INFO, &mut wrapping_key)
        .map_err(|error| VaultError::Crypto {
            operation: "derive recovery wrapping key",
            reason: error.to_string(),
        })?;
    Ok(wrapping_key)
}

fn recovery_envelope_aad(
    vault_id: VaultId,
    recovery_key_id: RecoveryKeyId,
    nonce: &[u8; XNONCE_LEN],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(192);
    aad.extend_from_slice(RECOVERY_AAD_DOMAIN);
    append_aad_component(&mut aad, RECOVERY_ENVELOPE_FORMAT.as_bytes());
    append_aad_component(&mut aad, &RECOVERY_ENVELOPE_VERSION.to_be_bytes());
    append_aad_component(&mut aad, vault_id.to_string().as_bytes());
    append_aad_component(&mut aad, recovery_key_id.to_string().as_bytes());
    append_aad_component(&mut aad, RECOVERY_ENVELOPE_ROLE.as_bytes());
    append_aad_component(&mut aad, RECOVERY_KDF.as_bytes());
    append_aad_component(&mut aad, RECOVERY_AEAD.as_bytes());
    append_aad_component(&mut aad, nonce);
    aad
}

fn append_aad_component(aad: &mut Vec<u8>, component: &[u8]) {
    let length = u32::try_from(component.len()).expect("recovery AAD component length fits u32");
    aad.extend_from_slice(&length.to_be_bytes());
    aad.extend_from_slice(component);
}

fn decode_canonical_hex<const LEN: usize>(
    value: &str,
    field: &'static str,
) -> VaultResult<[u8; LEN]> {
    if value.len() != LEN * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VaultError::InvalidVault {
            reason: format!("{field} is not canonical lowercase hexadecimal"),
        });
    }
    let mut decoded = [0_u8; LEN];
    hex::decode_to_slice(value, &mut decoded).map_err(|error| VaultError::InvalidVault {
        reason: format!("decode {field} failed: {error}"),
    })?;
    Ok(decoded)
}

fn recovery_hrp() -> Hrp {
    Hrp::parse(RECOVERY_KEY_HRP).expect("static recovery-key HRP must be valid")
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bech32::{Bech32, Bech32m};
    use serde_json::{json, Value};

    use super::{
        create_recovery_envelope, decrypt_recovery_envelope, recovery_hrp, wrap_recovery_envelope,
        RecoveryEnvelope, RecoveryKey, RecoveryKit, RECOVERY_AUTHORITY_LEN,
        RECOVERY_KEY_FORMAT_VERSION, XNONCE_LEN,
    };
    use crate::{RecoveryKeyId, SecretBytes, VaultError, VaultId};

    const SAMPLE_RECOVERY_CODE: &str =
        "knr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7a7n6ss";
    const SAMPLE_RECOVERY_CIPHERTEXT: &str =
        "c52d3680def12e2b4405c1a4df0c746643580cfdb2217d5398ff4e8e06d538dd3cfcc3b6a67a8010f30b908b58d4e588";

    fn sample_vault_id() -> VaultId {
        VaultId::from_str("vault_000102030405060708090a0b0c0d0e0f").expect("sample vault ID")
    }

    fn other_vault_id() -> VaultId {
        VaultId::from_str("vault_101112131415161718191a1b1c1d1e1f").expect("other vault ID")
    }

    fn sample_recovery_key() -> RecoveryKey {
        let mut authority = [0_u8; RECOVERY_AUTHORITY_LEN];
        for (index, byte) in authority.iter_mut().enumerate() {
            *byte = u8::try_from(index).expect("sample index fits u8");
        }
        RecoveryKey(authority)
    }

    fn sample_recovery_key_id() -> RecoveryKeyId {
        RecoveryKeyId::from_str("recovery_key_202122232425262728292a2b2c2d2e2f")
            .expect("sample recovery key ID")
    }

    fn deterministic_envelope() -> (RecoveryKey, RecoveryEnvelope, SecretBytes) {
        let recovery_key = sample_recovery_key();
        let vault_key = SecretBytes::new(vec![0x42; 32]);
        let nonce = [0x24; XNONCE_LEN];
        let envelope = wrap_recovery_envelope(
            sample_vault_id(),
            sample_recovery_key_id(),
            &vault_key,
            &recovery_key,
            &nonce,
        )
        .expect("wrap deterministic recovery envelope");
        (recovery_key, envelope, vault_key)
    }

    #[test]
    fn recovery_key_has_canonical_bech32m_round_trip() {
        let key = sample_recovery_key();
        let canonical = key.expose_canonical();

        assert_eq!(canonical, SAMPLE_RECOVERY_CODE);
        assert!(canonical.starts_with("knr1"));
        assert_eq!(canonical.len(), 63);
        assert_eq!(RecoveryKey::from_str(&canonical).expect("parse key"), key);

        let grouped_uppercase = canonical
            .to_ascii_uppercase()
            .as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).expect("ASCII chunk"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            RecoveryKey::from_str(&grouped_uppercase).expect("parse grouped uppercase"),
            key
        );
    }

    #[test]
    fn recovery_key_rejects_wrong_variant_hrp_version_length_case_and_checksum() {
        let key = sample_recovery_key();
        let canonical = key.expose_canonical();
        let mut payload = [0_u8; RECOVERY_AUTHORITY_LEN + 1];
        payload[0] = RECOVERY_KEY_FORMAT_VERSION;
        payload[1..].copy_from_slice(key.authority());

        let bech32 =
            bech32::encode::<Bech32>(recovery_hrp(), &payload).expect("encode Bech32 variant");
        let wrong_hrp = bech32::encode::<Bech32m>(
            bech32::Hrp::parse("bad").expect("valid alternate HRP"),
            &payload,
        )
        .expect("encode alternate HRP");
        payload[0] = RECOVERY_KEY_FORMAT_VERSION + 1;
        let future_version =
            bech32::encode::<Bech32m>(recovery_hrp(), &payload).expect("encode future version");
        let short =
            bech32::encode::<Bech32m>(recovery_hrp(), &payload[..32]).expect("encode short key");
        let mixed_case = format!("K{}", &canonical[1..]);
        let mut bad_checksum = canonical.clone();
        let replacement = if bad_checksum.ends_with('q') {
            "p"
        } else {
            "q"
        };
        bad_checksum.replace_range(bad_checksum.len() - 1.., replacement);

        for invalid in [
            bech32,
            wrong_hrp,
            future_version,
            short,
            mixed_case,
            bad_checksum,
            String::new(),
        ] {
            assert!(
                RecoveryKey::from_str(&invalid).is_err(),
                "accepted invalid recovery key"
            );
        }
    }

    #[test]
    fn recovery_key_debug_is_redacted() {
        let key = sample_recovery_key();
        let canonical = key.expose_canonical();
        let debug = format!("{key:?}");

        assert_eq!(debug, "RecoveryKey([REDACTED])");
        assert!(!debug.contains(&canonical));
        assert!(!debug.contains("00010203"));
    }

    #[test]
    fn recovery_kit_renders_canonical_grouped_and_qr_material_without_debug_leakage() {
        let key = sample_recovery_key();
        let canonical = key.expose_canonical();
        let vault_id = sample_vault_id();
        let recovery_key_id = sample_recovery_key_id();
        let kit = RecoveryKit::render(&key, vault_id, recovery_key_id, 1_800_000_000);

        assert_eq!(kit.canonical_code(), canonical);
        assert_eq!(kit.qr_payload(), canonical);
        assert!(kit.grouped_code().starts_with("KNR1 "));
        assert!(!kit.grouped_code().contains(&canonical));
        assert_eq!(kit.verification_groups().len(), 14);
        assert!(kit.verification_groups().iter().all(|group| {
            group.len() == 4
                && group
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        }));
        assert_eq!(kit.vault_id(), vault_id);
        assert_eq!(kit.recovery_key_id(), recovery_key_id);
        assert_eq!(kit.generated_at_unix_seconds(), 1_800_000_000);

        let debug = format!("{kit:?}");
        assert!(!debug.contains(&canonical));
        assert!(!debug.contains(kit.grouped_code()));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn generated_recovery_envelope_round_trips_same_vault_key() {
        let vault_id = sample_vault_id();
        let vault_key = SecretBytes::new(vec![0x5a; 32]);
        let (recovery_key, envelope) =
            create_recovery_envelope(vault_id, &vault_key).expect("create recovery envelope");

        let recovered = decrypt_recovery_envelope(&envelope, vault_id, &recovery_key)
            .expect("decrypt recovery envelope");

        assert_eq!(recovered.expose(), vault_key.expose());
        assert_eq!(envelope.vault_id(), vault_id);
        assert_eq!(envelope.version(), 1);
        assert_ne!(
            recovery_key.expose_canonical(),
            String::from_utf8(vec![0x5a; 32]).expect("ASCII vault key")
        );
    }

    #[test]
    fn recovery_envelope_json_is_strict_and_contains_no_recovery_authority() {
        let (recovery_key, envelope, _) = deterministic_envelope();
        let encoded = envelope.to_json().expect("serialize recovery envelope");
        let parsed = RecoveryEnvelope::parse_json(&encoded).expect("parse recovery envelope");
        let encoded_text = String::from_utf8(encoded.clone()).expect("JSON is UTF-8");

        assert_eq!(parsed, envelope);
        assert!(!encoded_text.contains(&recovery_key.expose_canonical()));
        assert!(!encoded_text
            .contains("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));

        let mut unknown: Value = serde_json::from_slice(&encoded).expect("parse JSON value");
        unknown
            .as_object_mut()
            .expect("envelope object")
            .insert("unexpected".to_owned(), json!(true));
        assert!(RecoveryEnvelope::parse_json(
            &serde_json::to_vec(&unknown).expect("serialize unknown-field envelope")
        )
        .is_err());
    }

    #[test]
    fn recovery_envelope_rejects_wrong_key_and_expected_vault() {
        let (recovery_key, envelope, _) = deterministic_envelope();
        let wrong_key = RecoveryKey([0xff; RECOVERY_AUTHORITY_LEN]);

        assert!(matches!(
            decrypt_recovery_envelope(&envelope, sample_vault_id(), &wrong_key)
                .expect_err("wrong recovery key"),
            VaultError::InvalidCredentials
        ));
        assert!(matches!(
            decrypt_recovery_envelope(&envelope, other_vault_id(), &recovery_key)
                .expect_err("wrong expected vault"),
            VaultError::InvalidVault { .. }
        ));
    }

    #[test]
    fn recovery_envelope_authenticates_identity_nonce_and_ciphertext() {
        let (recovery_key, envelope, _) = deterministic_envelope();
        let encoded = envelope.to_json().expect("serialize recovery envelope");

        for (field, replacement) in [
            (
                "recovery_key_id",
                json!("recovery_key_303132333435363738393a3b3c3d3e3f"),
            ),
            (
                "nonce_hex",
                json!("252424242424242424242424242424242424242424242424"),
            ),
        ] {
            let mut tampered: Value = serde_json::from_slice(&encoded).expect("parse envelope");
            tampered[field] = replacement;
            let tampered = RecoveryEnvelope::parse_json(
                &serde_json::to_vec(&tampered).expect("serialize tampered envelope"),
            )
            .expect("tampered envelope remains structurally valid");
            assert!(matches!(
                decrypt_recovery_envelope(&tampered, sample_vault_id(), &recovery_key)
                    .expect_err("authenticated metadata tamper rejected"),
                VaultError::InvalidCredentials
            ));
        }

        let mut transplanted: Value = serde_json::from_slice(&encoded).expect("parse envelope");
        transplanted["vault_id"] = json!(other_vault_id().to_string());
        let transplanted = RecoveryEnvelope::parse_json(
            &serde_json::to_vec(&transplanted).expect("serialize transplanted envelope"),
        )
        .expect("transplanted envelope remains structurally valid");
        assert!(matches!(
            decrypt_recovery_envelope(&transplanted, other_vault_id(), &recovery_key)
                .expect_err("vault identity tamper rejected by authentication"),
            VaultError::InvalidCredentials
        ));

        let mut tampered: Value = serde_json::from_slice(&encoded).expect("parse envelope");
        let ciphertext = tampered["ciphertext_hex"]
            .as_str()
            .expect("ciphertext string");
        let first_nibble = if ciphertext.starts_with('0') {
            "1"
        } else {
            "0"
        };
        tampered["ciphertext_hex"] = json!(format!("{first_nibble}{}", &ciphertext[1..]));
        let tampered = RecoveryEnvelope::parse_json(
            &serde_json::to_vec(&tampered).expect("serialize tampered ciphertext"),
        )
        .expect("tampered ciphertext remains structurally valid");
        assert!(matches!(
            decrypt_recovery_envelope(&tampered, sample_vault_id(), &recovery_key)
                .expect_err("ciphertext tamper rejected"),
            VaultError::InvalidCredentials
        ));
    }

    #[test]
    fn recovery_envelope_parser_rejects_future_or_malformed_documents() {
        let (_, envelope, _) = deterministic_envelope();
        let encoded = envelope.to_json().expect("serialize recovery envelope");

        for (field, replacement) in [
            ("version", json!(2)),
            ("format", json!("future-recovery-envelope")),
            ("role", json!("another-role")),
            ("kdf", json!("another-kdf")),
            ("aead", json!("another-aead")),
            ("nonce_hex", json!("00")),
            (
                "nonce_hex",
                json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ),
            ("ciphertext_hex", json!("00")),
        ] {
            let mut malformed: Value = serde_json::from_slice(&encoded).expect("parse envelope");
            malformed[field] = replacement;
            assert!(
                RecoveryEnvelope::parse_json(
                    &serde_json::to_vec(&malformed).expect("serialize malformed envelope")
                )
                .is_err(),
                "accepted malformed recovery envelope field {field}"
            );
        }

        assert!(RecoveryEnvelope::parse_json(b"not json").is_err());
        assert!(RecoveryEnvelope::parse_json(b"{}").is_err());
        assert!(RecoveryEnvelope::parse_json(&vec![b' '; 4_097]).is_err());
    }

    #[test]
    fn deterministic_recovery_envelope_is_stable() {
        let (recovery_key, first, vault_key) = deterministic_envelope();
        let nonce = [0x24; XNONCE_LEN];
        let second = wrap_recovery_envelope(
            sample_vault_id(),
            sample_recovery_key_id(),
            &vault_key,
            &recovery_key,
            &nonce,
        )
        .expect("wrap second deterministic envelope");

        assert_eq!(first, second);
        assert_eq!(first.ciphertext_hex, SAMPLE_RECOVERY_CIPHERTEXT);
        assert_eq!(
            decrypt_recovery_envelope(&first, sample_vault_id(), &recovery_key)
                .expect("decrypt deterministic envelope")
                .expose(),
            vault_key.expose()
        );
    }
}
