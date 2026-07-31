use std::fmt::{Display, Formatter};
use std::str::FromStr;

use rand_core::{OsRng, RngCore};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

const STABLE_ID_BYTE_LENGTH: usize = 16;
const STABLE_ID_HEX_LENGTH: usize = STABLE_ID_BYTE_LENGTH * 2;

/// Error returned when a stable domain identifier is not in canonical form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableIdParseError {
    expected_prefix: &'static str,
}

impl StableIdParseError {
    fn new(expected_prefix: &'static str) -> Self {
        Self { expected_prefix }
    }
}

impl Display for StableIdParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "invalid stable identifier; expected {:?} followed by {} lowercase hexadecimal characters",
            self.expected_prefix, STABLE_ID_HEX_LENGTH
        )
    }
}

impl std::error::Error for StableIdParseError {}

fn parse_stable_id(
    value: &str,
    expected_prefix: &'static str,
) -> Result<[u8; STABLE_ID_BYTE_LENGTH], StableIdParseError> {
    let invalid = || StableIdParseError::new(expected_prefix);
    let encoded = value.strip_prefix(expected_prefix).ok_or_else(invalid)?;

    if encoded.len() != STABLE_ID_HEX_LENGTH
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }

    let mut bytes = [0_u8; STABLE_ID_BYTE_LENGTH];
    hex::decode_to_slice(encoded, &mut bytes).map_err(|_| invalid())?;
    Ok(bytes)
}

macro_rules! define_stable_id {
    ($name:ident, $description:literal, $prefix:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; STABLE_ID_BYTE_LENGTH]);

        impl $name {
            #[doc = "Generates a new random stable identifier using the operating system CSPRNG."]
            #[must_use]
            pub fn generate() -> Self {
                let mut bytes = [0_u8; STABLE_ID_BYTE_LENGTH];
                OsRng.fill_bytes(&mut bytes);
                Self(bytes)
            }

            #[doc = "Returns the 128-bit value backing this stable identifier."]
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; STABLE_ID_BYTE_LENGTH] {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "{}{}", $prefix, hex::encode(self.0))
            }
        }

        impl FromStr for $name {
            type Err = StableIdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_stable_id(value, $prefix).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                String::deserialize(deserializer)?
                    .parse()
                    .map_err(de::Error::custom)
            }
        }
    };
}

define_stable_id!(
    VaultId,
    "Immutable identity of a KeptNear vault, independent of its filesystem path.",
    "vault_"
);
define_stable_id!(
    CredentialId,
    "Immutable identity of a credential item, independent of its mutable name.",
    "credential_"
);
define_stable_id!(
    SecretFieldId,
    "Immutable identity of one secret-bearing credential field.",
    "secret_field_"
);
define_stable_id!(
    RevisionId,
    "Immutable identity of one authenticated credential revision.",
    "revision_"
);
define_stable_id!(
    DeviceId,
    "Immutable local identity of the device that authored a credential revision.",
    "device_"
);
define_stable_id!(
    RecoveryKeyId,
    "Immutable identity of one offline recovery-key envelope generation.",
    "recovery_key_"
);

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fmt::{Debug, Display};
    use std::hash::Hash;
    use std::str::FromStr;

    use serde::de::DeserializeOwned;
    use serde::Serialize;

    use super::{CredentialId, DeviceId, RecoveryKeyId, RevisionId, SecretFieldId, VaultId};

    const SAMPLE_BYTES: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const SAMPLE_HEX: &str = "000102030405060708090a0b0c0d0e0f";
    const COLLISION_SAMPLE_SIZE: usize = 10_000;

    #[test]
    fn stable_ids_have_canonical_string_serialization() {
        let vault_id = VaultId(SAMPLE_BYTES);
        let credential_id = CredentialId(SAMPLE_BYTES);
        let secret_field_id = SecretFieldId(SAMPLE_BYTES);
        let revision_id = RevisionId(SAMPLE_BYTES);
        let device_id = DeviceId(SAMPLE_BYTES);
        let recovery_key_id = RecoveryKeyId(SAMPLE_BYTES);

        assert_eq!(vault_id.as_bytes(), &SAMPLE_BYTES);
        assert_eq!(credential_id.as_bytes(), &SAMPLE_BYTES);
        assert_eq!(secret_field_id.as_bytes(), &SAMPLE_BYTES);
        assert_eq!(revision_id.as_bytes(), &SAMPLE_BYTES);
        assert_eq!(device_id.as_bytes(), &SAMPLE_BYTES);
        assert_eq!(recovery_key_id.as_bytes(), &SAMPLE_BYTES);

        assert_canonical_round_trip(vault_id, &format!("vault_{SAMPLE_HEX}"));
        assert_canonical_round_trip(credential_id, &format!("credential_{SAMPLE_HEX}"));
        assert_canonical_round_trip(secret_field_id, &format!("secret_field_{SAMPLE_HEX}"));
        assert_canonical_round_trip(revision_id, &format!("revision_{SAMPLE_HEX}"));
        assert_canonical_round_trip(device_id, &format!("device_{SAMPLE_HEX}"));
        assert_canonical_round_trip(recovery_key_id, &format!("recovery_key_{SAMPLE_HEX}"));
    }

    #[test]
    fn stable_id_parsing_rejects_noncanonical_values_and_cross_kind_ids() {
        let uppercase_hex = SAMPLE_HEX.to_ascii_uppercase();
        let malformed_vault_ids = [
            SAMPLE_HEX.to_owned(),
            format!("Vault_{SAMPLE_HEX}"),
            format!("vault_{uppercase_hex}"),
            format!("vault_{}", &SAMPLE_HEX[..SAMPLE_HEX.len() - 1]),
            format!("vault_{SAMPLE_HEX}0"),
            format!("vault_{}g", &SAMPLE_HEX[..SAMPLE_HEX.len() - 1]),
            format!("credential_{SAMPLE_HEX}"),
            format!("vault_{SAMPLE_HEX} "),
        ];

        for value in malformed_vault_ids {
            assert!(
                value.parse::<VaultId>().is_err(),
                "accepted malformed vault ID: {value}"
            );
        }

        assert!(format!("vault_{SAMPLE_HEX}")
            .parse::<CredentialId>()
            .is_err());
        assert!(format!("credential_{SAMPLE_HEX}")
            .parse::<SecretFieldId>()
            .is_err());
        assert!(format!("revision_{SAMPLE_HEX}")
            .parse::<DeviceId>()
            .is_err());
        assert!(format!("device_{SAMPLE_HEX}")
            .parse::<RevisionId>()
            .is_err());
        assert!(format!("recovery_key_{SAMPLE_HEX}")
            .parse::<VaultId>()
            .is_err());
        assert!(format!("vault_{SAMPLE_HEX}")
            .parse::<RecoveryKeyId>()
            .is_err());
        assert!(serde_json::from_str::<VaultId>("123").is_err());
        assert!(serde_json::from_str::<CredentialId>("null").is_err());
        assert!(serde_json::from_str::<SecretFieldId>("{}").is_err());
        assert!(serde_json::from_str::<RevisionId>("[]").is_err());
        assert!(serde_json::from_str::<DeviceId>("false").is_err());
    }

    #[test]
    fn generated_stable_ids_are_unique_within_large_samples() {
        assert_generated_ids_are_unique(VaultId::generate);
        assert_generated_ids_are_unique(CredentialId::generate);
        assert_generated_ids_are_unique(SecretFieldId::generate);
        assert_generated_ids_are_unique(RevisionId::generate);
        assert_generated_ids_are_unique(DeviceId::generate);
        assert_generated_ids_are_unique(RecoveryKeyId::generate);
    }

    fn assert_canonical_round_trip<T>(value: T, expected: &str)
    where
        T: Debug + DeserializeOwned + Display + Eq + FromStr + Serialize,
        <T as FromStr>::Err: Debug,
    {
        assert_eq!(value.to_string(), expected);

        let encoded = serde_json::to_string(&value).expect("serialize stable ID");
        assert_eq!(encoded, format!("\"{expected}\""));
        assert_eq!(
            serde_json::from_str::<T>(&encoded).expect("deserialize stable ID"),
            value
        );
        assert_eq!(expected.parse::<T>().expect("parse stable ID"), value);
    }

    fn assert_generated_ids_are_unique<T>(generate: impl Fn() -> T)
    where
        T: Debug + Eq + Hash,
    {
        let mut generated = HashSet::with_capacity(COLLISION_SAMPLE_SIZE);
        for _ in 0..COLLISION_SAMPLE_SIZE {
            assert!(
                generated.insert(generate()),
                "generated a duplicate stable ID"
            );
        }
    }
}
