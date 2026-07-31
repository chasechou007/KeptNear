use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::credential_model::{
    Credential, CredentialFieldValue, CredentialSummary, SecretFieldKind,
};
use crate::stable_id::{DeviceId, RevisionId};

const CONTENT_DIGEST_BYTE_LENGTH: usize = 32;
const CONTENT_DIGEST_HEX_LENGTH: usize = CONTENT_DIGEST_BYTE_LENGTH * 2;
const CONTENT_DIGEST_PREFIX: &str = "sha256_";
const CONTENT_DIGEST_DOMAIN: &[u8] = b"KeptNear credential content digest v1";

/// Error returned when a content digest is not canonical SHA-256 text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentDigestParseError;

impl Display for ContentDigestParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "invalid content digest; expected {CONTENT_DIGEST_PREFIX} followed by \
             {CONTENT_DIGEST_HEX_LENGTH} lowercase hexadecimal characters"
        )
    }
}

impl std::error::Error for ContentDigestParseError {}

/// Domain-separated SHA-256 identity of canonical credential content.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentDigest([u8; CONTENT_DIGEST_BYTE_LENGTH]);

impl ContentDigest {
    /// Computes the canonical content identity for an identified credential.
    #[must_use]
    pub fn for_credential(credential: &Credential) -> Self {
        let mut writer = CanonicalDigestWriter::new();
        writer.bytes(CONTENT_DIGEST_DOMAIN);
        writer.bytes(credential.vault_id().as_bytes());
        writer.bytes(credential.credential_id().as_bytes());

        let draft = credential.draft();
        writer.text(&draft.title);
        writer.optional_text(draft.template_id.as_deref());
        writer.count(draft.fields.len());
        for field in &draft.fields {
            writer.text(&field.role);
            writer.optional_text(field.label.as_deref());
            match &field.value {
                CredentialFieldValue::Text { text } => {
                    writer.marker(0);
                    writer.text(text);
                }
                CredentialFieldValue::Secret {
                    secret_field_id,
                    kind,
                    secret,
                } => {
                    writer.marker(1);
                    writer.bytes(secret_field_id.as_bytes());
                    writer.secret_kind(*kind);
                    writer.bytes(secret.expose());
                }
            }
        }

        writer.count(draft.tags.len());
        for tag in &draft.tags {
            writer.text(tag);
        }
        writer.marker(u8::from(draft.favorite));
        Self(writer.finish())
    }

    /// Returns the 256-bit SHA-256 digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CONTENT_DIGEST_BYTE_LENGTH] {
        &self.0
    }
}

impl Display for ContentDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{CONTENT_DIGEST_PREFIX}{}", hex::encode(self.0))
    }
}

impl FromStr for ContentDigest {
    type Err = ContentDigestParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let encoded = value
            .strip_prefix(CONTENT_DIGEST_PREFIX)
            .ok_or(ContentDigestParseError)?;
        if encoded.len() != CONTENT_DIGEST_HEX_LENGTH
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ContentDigestParseError);
        }

        let mut bytes = [0_u8; CONTENT_DIGEST_BYTE_LENGTH];
        hex::decode_to_slice(encoded, &mut bytes).map_err(|_| ContentDigestParseError)?;
        Ok(Self(bytes))
    }
}

impl Serialize for ContentDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ContentDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

/// Error returned when revision ancestry or content identity is inconsistent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialRevisionError {
    reason: &'static str,
}

impl CredentialRevisionError {
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// Returns a non-secret explanation of the invalid revision metadata.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl Display for CredentialRevisionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid credential revision: {}", self.reason)
    }
}

impl std::error::Error for CredentialRevisionError {}

/// Encrypted lifecycle state carried by one credential revision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialLifecycle {
    /// Credential is visible in the ordinary active vault view.
    Active,
    /// Credential is retained but hidden from the ordinary active view.
    Archived,
    /// Credential is a deletion tombstone.
    Deleted,
}

/// One immutable authenticated snapshot in a credential's revision ancestry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CredentialRevision {
    revision_id: RevisionId,
    parent_revision_ids: Vec<RevisionId>,
    content_digest: ContentDigest,
    device_id: DeviceId,
    lifecycle: CredentialLifecycle,
    credential: Credential,
}

impl<'de> Deserialize<'de> for CredentialRevision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct CredentialRevisionWire {
            revision_id: RevisionId,
            parent_revision_ids: Vec<RevisionId>,
            content_digest: ContentDigest,
            device_id: DeviceId,
            lifecycle: CredentialLifecycle,
            credential: Credential,
        }

        let wire = CredentialRevisionWire::deserialize(deserializer)?;
        Self::with_metadata_and_lifecycle(
            wire.revision_id,
            wire.parent_revision_ids,
            wire.content_digest,
            wire.device_id,
            wire.lifecycle,
            wire.credential,
        )
        .map_err(de::Error::custom)
    }
}

impl CredentialRevision {
    /// Creates the first revision for a credential with no parent.
    pub fn initial(
        credential: Credential,
        device_id: DeviceId,
    ) -> Result<Self, CredentialRevisionError> {
        Self::initial_with_lifecycle(credential, device_id, CredentialLifecycle::Active)
    }

    /// Creates the first revision for a credential with an explicit lifecycle.
    pub fn initial_with_lifecycle(
        credential: Credential,
        device_id: DeviceId,
        lifecycle: CredentialLifecycle,
    ) -> Result<Self, CredentialRevisionError> {
        let revision = Self {
            revision_id: RevisionId::generate(),
            parent_revision_ids: Vec::new(),
            content_digest: ContentDigest::for_credential(&credential),
            device_id,
            lifecycle,
            credential,
        };
        revision.validate()?;
        Ok(revision)
    }

    /// Creates a descendant revision with one or more authenticated parents.
    pub fn descendant(
        credential: Credential,
        device_id: DeviceId,
        parent_revision_ids: Vec<RevisionId>,
    ) -> Result<Self, CredentialRevisionError> {
        Self::descendant_with_lifecycle(
            credential,
            device_id,
            parent_revision_ids,
            CredentialLifecycle::Active,
        )
    }

    /// Creates a descendant revision with an explicit encrypted lifecycle.
    pub fn descendant_with_lifecycle(
        credential: Credential,
        device_id: DeviceId,
        mut parent_revision_ids: Vec<RevisionId>,
        lifecycle: CredentialLifecycle,
    ) -> Result<Self, CredentialRevisionError> {
        if parent_revision_ids.is_empty() {
            return Err(CredentialRevisionError::new(
                "a descendant must name at least one parent",
            ));
        }
        parent_revision_ids.sort_unstable();
        if parent_revision_ids
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(CredentialRevisionError::new(
                "parent revision identities must be unique",
            ));
        }

        let revision_id = loop {
            let candidate = RevisionId::generate();
            if !parent_revision_ids.contains(&candidate) {
                break candidate;
            }
        };
        let revision = Self {
            revision_id,
            parent_revision_ids,
            content_digest: ContentDigest::for_credential(&credential),
            device_id,
            lifecycle,
            credential,
        };
        revision.validate()?;
        Ok(revision)
    }

    /// Restores a revision from explicit persisted metadata after validating it.
    pub fn with_metadata(
        revision_id: RevisionId,
        parent_revision_ids: Vec<RevisionId>,
        content_digest: ContentDigest,
        device_id: DeviceId,
        credential: Credential,
    ) -> Result<Self, CredentialRevisionError> {
        Self::with_metadata_and_lifecycle(
            revision_id,
            parent_revision_ids,
            content_digest,
            device_id,
            CredentialLifecycle::Active,
            credential,
        )
    }

    /// Restores a revision and explicit lifecycle from persisted metadata.
    pub fn with_metadata_and_lifecycle(
        revision_id: RevisionId,
        parent_revision_ids: Vec<RevisionId>,
        content_digest: ContentDigest,
        device_id: DeviceId,
        lifecycle: CredentialLifecycle,
        credential: Credential,
    ) -> Result<Self, CredentialRevisionError> {
        let revision = Self {
            revision_id,
            parent_revision_ids,
            content_digest,
            device_id,
            lifecycle,
            credential,
        };
        revision.validate()?;
        Ok(revision)
    }

    /// Returns the immutable revision identity.
    #[must_use]
    pub const fn revision_id(&self) -> RevisionId {
        self.revision_id
    }

    /// Returns canonical parent identities. Initial revisions have no parents.
    #[must_use]
    pub fn parent_revision_ids(&self) -> &[RevisionId] {
        &self.parent_revision_ids
    }

    /// Returns the canonical content digest committed by this revision.
    #[must_use]
    pub const fn content_digest(&self) -> ContentDigest {
        self.content_digest
    }

    /// Returns the immutable identity of the authoring device.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Returns the encrypted lifecycle represented by this revision.
    #[must_use]
    pub const fn lifecycle(&self) -> CredentialLifecycle {
        self.lifecycle
    }

    /// Returns the identified credential snapshot.
    #[must_use]
    pub const fn credential(&self) -> &Credential {
        &self.credential
    }

    /// Builds a non-secret summary after revision validation.
    pub fn summary(&self) -> Result<CredentialRevisionSummary, CredentialRevisionError> {
        self.validate()?;
        Ok(CredentialRevisionSummary {
            revision_id: self.revision_id,
            parent_revision_ids: self.parent_revision_ids.clone(),
            content_digest: self.content_digest,
            device_id: self.device_id,
            lifecycle: self.lifecycle,
            credential: self
                .credential
                .summary()
                .map_err(|_| CredentialRevisionError::new("credential identities are invalid"))?,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), CredentialRevisionError> {
        self.credential
            .validate()
            .map_err(|_| CredentialRevisionError::new("credential identities are invalid"))?;
        if self.parent_revision_ids.contains(&self.revision_id) {
            return Err(CredentialRevisionError::new(
                "a revision cannot name itself as a parent",
            ));
        }
        if !self
            .parent_revision_ids
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err(CredentialRevisionError::new(
                "parent revision identities must be canonical and unique",
            ));
        }
        if self.content_digest != ContentDigest::for_credential(&self.credential) {
            return Err(CredentialRevisionError::new(
                "content digest does not match credential content",
            ));
        }
        Ok(())
    }
}

/// Non-secret revision metadata and credential identity summary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRevisionSummary {
    /// Immutable revision identity.
    pub revision_id: RevisionId,
    /// Canonical authenticated parent revision identities.
    pub parent_revision_ids: Vec<RevisionId>,
    /// Canonical credential content digest.
    pub content_digest: ContentDigest,
    /// Identity of the authoring device.
    pub device_id: DeviceId,
    /// Encrypted lifecycle state represented by this revision.
    pub lifecycle: CredentialLifecycle,
    /// Value-free credential and secret-field identity summary.
    pub credential: CredentialSummary,
}

struct CanonicalDigestWriter(Sha256);

impl CanonicalDigestWriter {
    fn new() -> Self {
        Self(Sha256::new())
    }

    fn marker(&mut self, marker: u8) {
        self.0.update([marker]);
    }

    fn count(&mut self, count: usize) {
        self.0.update((count as u64).to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.count(value.len());
        self.0.update(value);
    }

    fn text(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn optional_text(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.marker(1);
                self.text(value);
            }
            None => self.marker(0),
        }
    }

    fn secret_kind(&mut self, kind: SecretFieldKind) {
        self.text(kind.as_str());
    }

    fn finish(self) -> [u8; CONTENT_DIGEST_BYTE_LENGTH] {
        self.0.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Credential, CredentialDraft, CredentialField, CredentialFieldValue, CredentialId, DeviceId,
        RevisionId, SecretBytes, SecretFieldId, SecretFieldKind, VaultId,
    };

    use super::{ContentDigest, CredentialLifecycle, CredentialRevision};

    #[test]
    fn content_digest_is_canonical_and_tracks_every_credential_value() {
        let credential = sample_credential();
        let digest = ContentDigest::for_credential(&credential);
        let encoded = serde_json::to_string(&digest).expect("serialize content digest");
        assert_eq!(
            serde_json::from_str::<ContentDigest>(&encoded).expect("deserialize content digest"),
            digest
        );
        assert_eq!(
            digest
                .to_string()
                .parse::<ContentDigest>()
                .expect("parse digest"),
            digest
        );
        assert!(digest.to_string().starts_with("sha256_"));
        assert_eq!(digest.to_string().len(), "sha256_".len() + 64);

        let mut renamed = credential.clone();
        renamed.draft_mut().title = "Renamed credential".to_owned();
        assert_ne!(ContentDigest::for_credential(&renamed), digest);

        let mut changed_secret = credential.clone();
        let CredentialFieldValue::Secret { secret, .. } =
            &mut changed_secret.draft_mut().fields[1].value
        else {
            panic!("expected secret field");
        };
        *secret = SecretBytes::new(b"different-secret-marker".to_vec());
        assert_ne!(ContentDigest::for_credential(&changed_secret), digest);

        let mut reordered = credential;
        reordered.draft_mut().fields.swap(0, 1);
        assert_ne!(ContentDigest::for_credential(&reordered), digest);
    }

    #[test]
    fn malformed_content_digests_fail_closed() {
        let digest = ContentDigest::for_credential(&sample_credential()).to_string();
        for malformed in [
            digest.trim_start_matches("sha256_").to_owned(),
            digest.to_ascii_uppercase(),
            format!("{digest}0"),
            digest[..digest.len() - 1].to_owned(),
            format!("sha1_{}", "0".repeat(40)),
        ] {
            assert!(
                malformed.parse::<ContentDigest>().is_err(),
                "accepted malformed content digest: {malformed}"
            );
        }
        assert!(serde_json::from_str::<ContentDigest>("null").is_err());
    }

    #[test]
    fn revision_ancestry_is_canonical_and_summary_contains_no_field_values() {
        let initial = CredentialRevision::initial(sample_credential(), DeviceId::generate())
            .expect("create initial revision");
        assert!(initial.parent_revision_ids().is_empty());

        let other_parent = RevisionId::generate();
        let mut expected_parents = vec![initial.revision_id(), other_parent];
        expected_parents.sort_unstable();
        let descendant = CredentialRevision::descendant(
            initial.credential().clone(),
            DeviceId::generate(),
            vec![other_parent, initial.revision_id()],
        )
        .expect("create descendant");
        assert_eq!(descendant.parent_revision_ids(), expected_parents);

        let summary = descendant.summary().expect("summarize revision");
        assert_eq!(summary.revision_id, descendant.revision_id());
        assert_eq!(summary.parent_revision_ids, expected_parents);
        assert_eq!(summary.content_digest, descendant.content_digest());
        assert_eq!(summary.device_id, descendant.device_id());
        assert_eq!(summary.lifecycle, CredentialLifecycle::Active);

        let encoded = serde_json::to_string(&summary).expect("serialize revision summary");
        assert!(!encoded.contains("private-account-marker"));
        assert!(!encoded.contains("synthetic-secret-marker"));
    }

    #[test]
    fn revision_validation_rejects_invalid_ancestry_and_content_digest() {
        let credential = sample_credential();
        let digest = ContentDigest::for_credential(&credential);
        let revision_id = RevisionId::generate();
        let parent = RevisionId::generate();
        let device_id = DeviceId::generate();

        let duplicate = CredentialRevision::with_metadata(
            revision_id,
            vec![parent, parent],
            digest,
            device_id,
            credential.clone(),
        )
        .expect_err("duplicate parents");
        assert!(duplicate.reason().contains("canonical and unique"));

        let self_parent = CredentialRevision::with_metadata(
            revision_id,
            vec![revision_id],
            digest,
            device_id,
            credential.clone(),
        )
        .expect_err("self parent");
        assert!(self_parent.reason().contains("itself"));

        let wrong_digest = ContentDigest::for_credential(
            &Credential::new(VaultId::generate(), credential.draft().clone())
                .expect("create comparison credential"),
        );
        let mismatch = CredentialRevision::with_metadata(
            revision_id,
            vec![parent],
            wrong_digest,
            device_id,
            credential,
        )
        .expect_err("mismatched content digest");
        assert!(mismatch.reason().contains("content digest"));

        assert!(CredentialRevision::descendant(
            sample_credential(),
            DeviceId::generate(),
            Vec::new(),
        )
        .is_err());
    }

    #[test]
    fn revision_parsing_rejects_malformed_identity_ancestry_and_digest() {
        let revision = CredentialRevision::descendant(
            sample_credential(),
            DeviceId::generate(),
            vec![RevisionId::generate(), RevisionId::generate()],
        )
        .expect("create parser fixture");
        let encoded = serde_json::to_value(&revision).expect("serialize revision");

        let mut duplicate_parents = encoded.clone();
        let parent = revision.parent_revision_ids()[0].to_string();
        duplicate_parents["parent_revision_ids"] = serde_json::json!([parent, parent]);
        assert!(serde_json::from_value::<CredentialRevision>(duplicate_parents).is_err());

        let mut unknown_lifecycle = encoded.clone();
        unknown_lifecycle["lifecycle"] = serde_json::json!("conflicted");
        assert!(serde_json::from_value::<CredentialRevision>(unknown_lifecycle).is_err());

        let mut noncanonical_parents = encoded.clone();
        noncanonical_parents["parent_revision_ids"] = serde_json::json!([
            revision.parent_revision_ids()[1].to_string(),
            revision.parent_revision_ids()[0].to_string()
        ]);
        assert!(serde_json::from_value::<CredentialRevision>(noncanonical_parents).is_err());

        let mut self_parent = encoded.clone();
        self_parent["parent_revision_ids"] =
            serde_json::json!([revision.revision_id().to_string()]);
        assert!(serde_json::from_value::<CredentialRevision>(self_parent).is_err());

        let mut malformed_revision_id = encoded.clone();
        malformed_revision_id["revision_id"] =
            serde_json::Value::String(revision.device_id().to_string());
        assert!(serde_json::from_value::<CredentialRevision>(malformed_revision_id).is_err());

        let mut malformed_device_id = encoded.clone();
        malformed_device_id["device_id"] =
            serde_json::Value::String(revision.device_id().to_string().to_ascii_uppercase());
        assert!(serde_json::from_value::<CredentialRevision>(malformed_device_id).is_err());

        let mut changed_content = encoded.clone();
        changed_content["credential"]["draft"]["title"] =
            serde_json::Value::String("Changed without digest".to_owned());
        assert!(serde_json::from_value::<CredentialRevision>(changed_content).is_err());

        let mut unknown_field = encoded;
        unknown_field["unexpected"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<CredentialRevision>(unknown_field).is_err());
    }

    fn sample_credential() -> Credential {
        Credential::with_id(
            VaultId::generate(),
            CredentialId::generate(),
            CredentialDraft {
                title: "Automation token".to_owned(),
                template_id: Some("api-token".to_owned()),
                fields: vec![
                    CredentialField::text("account", "private-account-marker"),
                    CredentialField::secret_with_id(
                        "token",
                        SecretFieldId::generate(),
                        SecretFieldKind::ApiToken,
                        SecretBytes::new(b"synthetic-secret-marker".to_vec()),
                    ),
                ],
                tags: vec!["development".to_owned()],
                favorite: true,
            },
        )
        .expect("create sample credential")
    }
}
