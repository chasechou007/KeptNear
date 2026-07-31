use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const CONSUMER_SEED_LENGTH: usize = 32;
/// Maximum canonical byte length of one pairing-profile identifier.
pub const MAX_PAIRING_PROFILE_ID_BYTES: usize = 64;

/// First-party adapter namespace for one independently paired Consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientIdentityKind {
    /// Public KeptNear command-line client.
    Cli,
    /// Local KeptNear MCP stdio adapter.
    Mcp,
}

/// Stable local selector for one independently paired Consumer identity.
///
/// Profile identifiers are non-secret configuration labels. They are
/// canonicalized to lowercase ASCII and never sent through the Broker
/// protocol. Reusing one profile intentionally reuses one Consumer permission
/// set; distinct profiles use distinct device-local signing keys.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct PairingProfileId(String);

impl PairingProfileId {
    /// Creates one canonical profile identifier.
    ///
    /// The first and last characters must be ASCII alphanumeric. Interior
    /// characters may additionally contain `.`, `_`, or `-`.
    pub fn new(value: &str) -> Result<Self, PairingProfileIdError> {
        if value.is_empty() || value.len() > MAX_PAIRING_PROFILE_ID_BYTES || !value.is_ascii() {
            return Err(PairingProfileIdError);
        }
        let normalized = value.to_ascii_lowercase();
        let bytes = normalized.as_bytes();
        if !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(PairingProfileIdError);
        }
        Ok(Self(normalized))
    }

    /// Returns the canonical non-secret configuration identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn is_default(&self) -> bool {
        self.0 == "default"
    }
}

impl Default for PairingProfileId {
    fn default() -> Self {
        Self("default".to_owned())
    }
}

impl FromStr for PairingProfileId {
    type Err = PairingProfileIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Debug for PairingProfileId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("PairingProfileId")
            .field(&"<profile>")
            .finish()
    }
}

/// Sanitized failure for an invalid pairing-profile identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingProfileIdError;

impl Display for PairingProfileIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeptNear pairing profile identifier is invalid")
    }
}

impl std::error::Error for PairingProfileIdError {}

/// Device-local Ed25519 identity used only to authenticate one local adapter.
pub struct ConsumerIdentity {
    seed: Zeroizing<[u8; CONSUMER_SEED_LENGTH]>,
}

impl ConsumerIdentity {
    pub(crate) fn generate() -> Self {
        let mut seed = [0_u8; CONSUMER_SEED_LENGTH];
        OsRng.fill_bytes(&mut seed);
        Self {
            seed: Zeroizing::new(seed),
        }
    }

    pub(crate) fn from_stored_bytes(mut bytes: Vec<u8>) -> Result<Self, IdentityStoreError> {
        if bytes.len() != CONSUMER_SEED_LENGTH {
            bytes.zeroize();
            return Err(IdentityStoreError::InvalidMaterial);
        }
        let mut seed = [0_u8; CONSUMER_SEED_LENGTH];
        seed.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self {
            seed: Zeroizing::new(seed),
        })
    }

    pub(crate) fn public_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.seed)
            .verifying_key()
            .to_bytes()
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.seed).sign(message).to_bytes()
    }

    pub(crate) fn expose_seed(&self) -> &[u8; CONSUMER_SEED_LENGTH] {
        &self.seed
    }
}

impl Debug for ConsumerIdentity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsumerIdentity")
            .field("seed", &"<redacted>")
            .finish()
    }
}

/// Sanitized device credential-store failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityStoreError {
    /// The platform credential store could not complete the operation.
    Unavailable,
    /// Stored identity bytes have an invalid length.
    InvalidMaterial,
    /// Another process created the stable item first.
    AlreadyExists,
}

impl Display for IdentityStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Unavailable => "MCP Consumer identity store is unavailable",
            Self::InvalidMaterial => "MCP Consumer identity material is invalid",
            Self::AlreadyExists => "MCP Consumer identity already exists",
        };
        formatter.write_str(label)
    }
}

impl std::error::Error for IdentityStoreError {}

pub(crate) trait ConsumerIdentityStore {
    fn load(&self) -> Result<Option<ConsumerIdentity>, IdentityStoreError>;

    fn create(&self, identity: &ConsumerIdentity) -> Result<(), IdentityStoreError>;
}

pub(crate) fn load_or_create_identity(
    store: &impl ConsumerIdentityStore,
) -> Result<ConsumerIdentity, IdentityStoreError> {
    if let Some(identity) = store.load()? {
        return Ok(identity);
    }

    let identity = ConsumerIdentity::generate();
    match store.create(&identity) {
        Ok(()) => Ok(identity),
        Err(IdentityStoreError::AlreadyExists) => {
            store.load()?.ok_or(IdentityStoreError::Unavailable)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use super::*;

    struct MemoryProfileIdentityStore {
        profiles: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        profile: PairingProfileId,
    }

    impl MemoryProfileIdentityStore {
        fn for_profile(
            profiles: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
            profile: PairingProfileId,
        ) -> Self {
            Self { profiles, profile }
        }
    }

    impl ConsumerIdentityStore for MemoryProfileIdentityStore {
        fn load(&self) -> Result<Option<ConsumerIdentity>, IdentityStoreError> {
            self.profiles
                .lock()
                .expect("profiles")
                .get(self.profile.as_str())
                .cloned()
                .map(ConsumerIdentity::from_stored_bytes)
                .transpose()
        }

        fn create(&self, identity: &ConsumerIdentity) -> Result<(), IdentityStoreError> {
            let mut profiles = self.profiles.lock().expect("profiles");
            if profiles.contains_key(self.profile.as_str()) {
                return Err(IdentityStoreError::AlreadyExists);
            }
            profiles.insert(
                self.profile.as_str().to_owned(),
                identity.expose_seed().to_vec(),
            );
            Ok(())
        }
    }

    #[test]
    fn identity_signs_without_exposing_seed_in_debug() {
        let identity = ConsumerIdentity::from_stored_bytes(vec![0x71; CONSUMER_SEED_LENGTH])
            .expect("identity");
        let message = b"KeptNear MCP identity test";
        let signature = identity.sign(message);
        let verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(&identity.public_key()).expect("public key");

        verifying_key
            .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
            .expect("signature");
        assert!(!format!("{identity:?}").contains(&"71".repeat(CONSUMER_SEED_LENGTH)));
    }

    #[test]
    fn malformed_stored_identity_is_rejected_after_zeroizing_the_input_copy() {
        assert!(matches!(
            ConsumerIdentity::from_stored_bytes(vec![0x72; CONSUMER_SEED_LENGTH - 1]),
            Err(IdentityStoreError::InvalidMaterial)
        ));
    }

    #[test]
    fn pairing_profile_ids_are_bounded_canonical_and_path_free() {
        assert_eq!(
            PairingProfileId::new("Codex.Release_1")
                .expect("profile")
                .as_str(),
            "codex.release_1"
        );
        assert_eq!(PairingProfileId::default().as_str(), "default");
        for invalid in [
            "",
            "-codex",
            "codex-",
            "codex/profile",
            "codex profile",
            "codex\nprofile",
            "中文",
        ] {
            assert_eq!(PairingProfileId::new(invalid), Err(PairingProfileIdError));
        }
        assert_eq!(
            PairingProfileId::new(&"a".repeat(MAX_PAIRING_PROFILE_ID_BYTES + 1)),
            Err(PairingProfileIdError)
        );
        assert!(!format!("{:?}", PairingProfileId::default()).contains("default"));
    }

    #[test]
    fn distinct_profiles_create_distinct_identities_and_same_profile_reuses_one() {
        let profiles = Arc::new(Mutex::new(BTreeMap::new()));
        let default_store = MemoryProfileIdentityStore::for_profile(
            Arc::clone(&profiles),
            PairingProfileId::default(),
        );
        let default_identity = load_or_create_identity(&default_store).expect("default identity");
        let repeated_default = load_or_create_identity(&default_store).expect("repeat identity");
        assert_eq!(default_identity.public_key(), repeated_default.public_key());

        let codex_store = MemoryProfileIdentityStore::for_profile(
            Arc::clone(&profiles),
            PairingProfileId::new("codex").expect("profile"),
        );
        let codex_identity = load_or_create_identity(&codex_store).expect("Codex identity");
        let repeated_codex = load_or_create_identity(&codex_store).expect("repeat Codex identity");
        assert_ne!(default_identity.public_key(), codex_identity.public_key());
        assert_eq!(codex_identity.public_key(), repeated_codex.public_key());
        assert_eq!(profiles.lock().expect("profiles").len(), 2);
    }
}
