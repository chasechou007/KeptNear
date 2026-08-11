use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::controller_authority_contract::{
    CONTROLLER_ID_LENGTH, CONTROLLER_NONCE_LENGTH, CONTROLLER_PROTOCOL_ID_LENGTH,
};

const CONTROLLER_ID_PREFIX: &str = "controller_";
const CONTROLLER_SESSION_ID_PREFIX: &str = "controller_session_";
const HUMAN_CONTROL_REQUEST_ID_PREFIX: &str = "control_request_";
const CONTROLLER_NONCE_PREFIX: &str = "controller_nonce_";
const CONTROLLER_DEADLINE_PREFIX: &str = "controller_deadline_";

/// Fixed parse failure for a non-canonical human-controller value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanControlTypeParseError {
    /// The value does not use the exact prefix, length, or lowercase hexadecimal encoding.
    InvalidEncoding,
    /// A monotonic deadline token is zero or is not canonical unsigned decimal.
    InvalidDeadline,
}

impl Display for HumanControlTypeParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid human-controller value",
            Self::InvalidDeadline => "invalid human-controller deadline",
        })
    }
}

impl std::error::Error for HumanControlTypeParseError {}

fn parse_prefixed_hex<const N: usize>(
    value: &str,
    prefix: &str,
) -> Result<[u8; N], HumanControlTypeParseError> {
    let encoded = value
        .strip_prefix(prefix)
        .ok_or(HumanControlTypeParseError::InvalidEncoding)?;
    if encoded.len() != N * 2
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(HumanControlTypeParseError::InvalidEncoding);
    }
    let mut bytes = [0_u8; N];
    hex::decode_to_slice(encoded, &mut bytes)
        .map_err(|_| HumanControlTypeParseError::InvalidEncoding)?;
    Ok(bytes)
}

macro_rules! define_public_hex_type {
    ($name:ident, $length:expr, $prefix:expr, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $length]);

        impl $name {
            /// Builds the typed value from its exact bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            /// Returns the exact bytes backing this value.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "{}{}", $prefix, hex::encode(self.0))
            }
        }

        impl Debug for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                Display::fmt(self, formatter)
            }
        }

        impl FromStr for $name {
            type Err = HumanControlTypeParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_prefixed_hex(value, $prefix).map(Self)
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
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

define_public_hex_type!(
    ControllerId,
    CONTROLLER_ID_LENGTH,
    CONTROLLER_ID_PREFIX,
    "Stable public identity derived from one controller public key."
);

define_public_hex_type!(
    ControllerSessionId,
    CONTROLLER_PROTOCOL_ID_LENGTH,
    CONTROLLER_SESSION_ID_PREFIX,
    "Ephemeral identity of one negotiated human-controller connection."
);

define_public_hex_type!(
    HumanControlRequestId,
    CONTROLLER_PROTOCOL_ID_LENGTH,
    HUMAN_CONTROL_REQUEST_ID_PREFIX,
    "Immutable correlation identity of one human-control request."
);

impl HumanControlRequestId {
    /// Generates a fresh request identity from the operating-system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; CONTROLLER_PROTOCOL_ID_LENGTH];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl ControllerSessionId {
    /// Generates a fresh session identity from the operating-system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; CONTROLLER_PROTOCOL_ID_LENGTH];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// One independently generated controller challenge nonce.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ControllerNonce([u8; CONTROLLER_NONCE_LENGTH]);

impl ControllerNonce {
    /// Generates a fresh nonce from the operating-system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; CONTROLLER_NONCE_LENGTH];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Builds a nonce from exact bytes, primarily for protocol verification.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CONTROLLER_NONCE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the nonce bytes for transcript construction.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CONTROLLER_NONCE_LENGTH] {
        &self.0
    }
}

impl Display for ControllerNonce {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}{}",
            CONTROLLER_NONCE_PREFIX,
            hex::encode(self.0)
        )
    }
}

impl Debug for ControllerNonce {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControllerNonce(<redacted>)")
    }
}

impl FromStr for ControllerNonce {
    type Err = HumanControlTypeParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_prefixed_hex(value, CONTROLLER_NONCE_PREFIX).map(Self)
    }
}

impl Serialize for ControllerNonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ControllerNonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

/// Opaque process-local monotonic deadline token bound into a controller proof.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ControllerDeadline(u64);

impl ControllerDeadline {
    /// Creates a non-zero opaque token.
    pub fn new(value: u64) -> Result<Self, HumanControlTypeParseError> {
        if value == 0 {
            return Err(HumanControlTypeParseError::InvalidDeadline);
        }
        Ok(Self(value))
    }

    /// Returns the opaque integer bound into the signed transcript.
    #[must_use]
    pub const fn token(self) -> u64 {
        self.0
    }
}

impl Display for ControllerDeadline {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{CONTROLLER_DEADLINE_PREFIX}{}", self.0)
    }
}

impl Debug for ControllerDeadline {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControllerDeadline(<opaque>)")
    }
}

impl FromStr for ControllerDeadline {
    type Err = HumanControlTypeParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let encoded = value
            .strip_prefix(CONTROLLER_DEADLINE_PREFIX)
            .ok_or(HumanControlTypeParseError::InvalidDeadline)?;
        if encoded.is_empty()
            || (encoded.len() > 1 && encoded.starts_with('0'))
            || !encoded.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(HumanControlTypeParseError::InvalidDeadline);
        }
        let token = encoded
            .parse::<u64>()
            .map_err(|_| HumanControlTypeParseError::InvalidDeadline)?;
        Self::new(token)
    }
}

impl Serialize for ControllerDeadline {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ControllerDeadline {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_values_round_trip_only_in_canonical_form() {
        let controller = ControllerId::from_bytes([0xab; CONTROLLER_ID_LENGTH]);
        let session = ControllerSessionId::from_bytes([0x12; CONTROLLER_PROTOCOL_ID_LENGTH]);
        let nonce = ControllerNonce::from_bytes([0x34; CONTROLLER_NONCE_LENGTH]);
        let request = HumanControlRequestId::from_bytes([0x56; CONTROLLER_PROTOCOL_ID_LENGTH]);
        let deadline = ControllerDeadline::new(42).expect("deadline");

        assert_eq!(controller.to_string().parse(), Ok(controller));
        assert_eq!(session.to_string().parse(), Ok(session));
        assert_eq!(nonce.to_string().parse(), Ok(nonce));
        assert_eq!(request.to_string().parse(), Ok(request));
        assert_eq!(deadline.to_string().parse(), Ok(deadline));
        assert!(controller
            .to_string()
            .to_uppercase()
            .parse::<ControllerId>()
            .is_err());
        assert!("controller_session_12"
            .parse::<ControllerSessionId>()
            .is_err());
        assert!("controller_nonce_00".parse::<ControllerNonce>().is_err());
        assert!("controller_deadline_00"
            .parse::<ControllerDeadline>()
            .is_err());
        assert!("controller_deadline_0"
            .parse::<ControllerDeadline>()
            .is_err());
    }

    #[test]
    fn authentication_material_has_non_reflective_debug_output() {
        let nonce = ControllerNonce::from_bytes([0x5a; CONTROLLER_NONCE_LENGTH]);
        let deadline = ControllerDeadline::new(u64::MAX).expect("deadline");
        assert_eq!(format!("{nonce:?}"), "ControllerNonce(<redacted>)");
        assert_eq!(format!("{deadline:?}"), "ControllerDeadline(<opaque>)");
        assert!(!format!("{nonce:?}").contains(&hex::encode([0x5a; 32])));
    }
}
