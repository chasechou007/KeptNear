use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::stable_id::{CredentialId, SecretFieldId, VaultId};
use crate::types::{
    CreditCardItem, LoginItem, SecretBytes, SecureNoteItem, SoftwareLicenseItem, VaultItemContent,
    VaultItemDraft,
};

/// Error returned when a credential-model value is unknown or not canonical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialModelParseError {
    expected: &'static str,
}

impl CredentialModelParseError {
    const fn new(expected: &'static str) -> Self {
        Self { expected }
    }
}

impl Display for CredentialModelParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "invalid credential-model value; expected {}",
            self.expected
        )
    }
}

impl std::error::Error for CredentialModelParseError {}

macro_rules! define_string_enum {
    (
        $name:ident,
        $description:literal,
        $expected:literal,
        { $($variant:ident => $serialized:literal),+ $(,)? }
    ) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub enum $name {
            $(
                #[doc = "A supported canonical value."]
                $variant,
            )+
        }

        impl $name {
            /// Every value supported by the current credential-model version.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// Returns the canonical versioned string representation.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $serialized),+
                }
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = CredentialModelParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($serialized => Ok(Self::$variant),)+
                    _ => Err(CredentialModelParseError::new($expected)),
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
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

define_string_enum!(
    SecretFieldKind,
    "Provider-neutral classification of a secret-bearing credential field.",
    "a supported secret field kind",
    {
        Password => "password",
        ApiToken => "api-token",
        ApiKey => "api-key",
        TotpSeed => "totp-seed",
        PrivateKey => "private-key",
        Certificate => "certificate",
        GenericSecret => "generic-secret",
    }
);

/// One built-in presentation template over the extensible credential model.
///
/// Template identifiers and field roles are presentation hints, not
/// authorization identities. The persisted model remains open to custom
/// template identifiers and roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialTemplateDefinition {
    /// Stable presentation identifier persisted in `CredentialDraft::template_id`.
    pub id: &'static str,
    /// Provider-neutral role used for the template's primary secret field.
    pub primary_secret_role: &'static str,
    /// Provider-neutral kind used for the template's primary secret field.
    pub primary_secret_kind: SecretFieldKind,
    /// Whether the friendly creation flow requires a non-empty primary secret.
    pub primary_secret_required: bool,
    /// Optional non-secret roles offered by the friendly creation flow.
    pub optional_text_roles: &'static [&'static str],
}

/// Offline built-in templates exposed by the human control plane.
///
/// This catalog contains no provider configuration and requires no network
/// lookup. Clients may add presentation-only templates while persisting the
/// same open `CredentialDraft` schema.
pub const BUILT_IN_CREDENTIAL_TEMPLATES: &[CredentialTemplateDefinition] = &[
    CredentialTemplateDefinition {
        id: "login",
        primary_secret_role: "password",
        primary_secret_kind: SecretFieldKind::Password,
        primary_secret_required: false,
        optional_text_roles: &["username", "url", "notes"],
    },
    CredentialTemplateDefinition {
        id: "api-token",
        primary_secret_role: "token",
        primary_secret_kind: SecretFieldKind::ApiToken,
        primary_secret_required: true,
        optional_text_roles: &["expiry", "notes"],
    },
    CredentialTemplateDefinition {
        id: "api-key",
        primary_secret_role: "api-key",
        primary_secret_kind: SecretFieldKind::ApiKey,
        primary_secret_required: true,
        optional_text_roles: &["expiry", "notes"],
    },
    CredentialTemplateDefinition {
        id: "ssh-key",
        primary_secret_role: "private-key",
        primary_secret_kind: SecretFieldKind::PrivateKey,
        primary_secret_required: true,
        optional_text_roles: &["notes"],
    },
    CredentialTemplateDefinition {
        id: "certificate",
        primary_secret_role: "certificate",
        primary_secret_kind: SecretFieldKind::Certificate,
        primary_secret_required: true,
        optional_text_roles: &["expiry", "notes"],
    },
    CredentialTemplateDefinition {
        id: "secure-note",
        primary_secret_role: "body",
        primary_secret_kind: SecretFieldKind::GenericSecret,
        primary_secret_required: false,
        optional_text_roles: &[],
    },
    CredentialTemplateDefinition {
        id: "custom",
        primary_secret_role: "secret",
        primary_secret_kind: SecretFieldKind::GenericSecret,
        primary_secret_required: true,
        optional_text_roles: &["notes"],
    },
];

/// Finds one built-in presentation template by its exact canonical identifier.
#[must_use]
pub fn built_in_credential_template(id: &str) -> Option<&'static CredentialTemplateDefinition> {
    BUILT_IN_CREDENTIAL_TEMPLATES
        .iter()
        .find(|template| template.id == id)
}

/// Error returned when credential identities are structurally inconsistent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialValidationError {
    reason: &'static str,
}

impl CredentialValidationError {
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// Returns a non-secret explanation of the invalid credential structure.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl Display for CredentialValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid credential: {}", self.reason)
    }
}

impl std::error::Error for CredentialValidationError {}

/// One identified credential persisted inside a specific vault.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Credential {
    vault_id: VaultId,
    credential_id: CredentialId,
    draft: CredentialDraft,
}

impl Credential {
    /// Creates a new credential with a random immutable credential identity.
    pub fn new(
        vault_id: VaultId,
        draft: CredentialDraft,
    ) -> Result<Self, CredentialValidationError> {
        Self::with_id(vault_id, CredentialId::generate(), draft)
    }

    /// Restores a credential with identities already allocated by persistence or migration.
    pub fn with_id(
        vault_id: VaultId,
        credential_id: CredentialId,
        draft: CredentialDraft,
    ) -> Result<Self, CredentialValidationError> {
        let credential = Self {
            vault_id,
            credential_id,
            draft,
        };
        credential.validate()?;
        Ok(credential)
    }

    /// Returns the immutable vault identity containing this credential.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Returns the immutable credential identity.
    #[must_use]
    pub const fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    /// Returns the editable credential content.
    #[must_use]
    pub const fn draft(&self) -> &CredentialDraft {
        &self.draft
    }

    /// Returns the editable credential content while keeping record identities fixed.
    #[must_use]
    pub fn draft_mut(&mut self) -> &mut CredentialDraft {
        &mut self.draft
    }

    /// Validates credential identity invariants.
    pub fn validate(&self) -> Result<(), CredentialValidationError> {
        let mut secret_field_ids = HashSet::new();
        for field in self.draft.secret_fields() {
            let Some(secret_field_id) = field.secret_field_id() else {
                return Err(CredentialValidationError::new(
                    "secret field is missing its stable identity",
                ));
            };
            if !secret_field_ids.insert(secret_field_id) {
                return Err(CredentialValidationError::new(
                    "secret-field identities must be unique",
                ));
            }
        }
        Ok(())
    }

    /// Builds a non-secret summary that retains authorization identities.
    pub fn summary(&self) -> Result<CredentialSummary, CredentialValidationError> {
        self.validate()?;
        Ok(CredentialSummary {
            vault_id: self.vault_id,
            credential_id: self.credential_id,
            title: self.draft.title.clone(),
            template_id: self.draft.template_id.clone(),
            secret_fields: self
                .draft
                .secret_fields()
                .filter_map(SecretFieldSummary::from_field)
                .collect(),
            tags: self.draft.tags.clone(),
            favorite: self.draft.favorite,
        })
    }
}

impl<'de> Deserialize<'de> for Credential {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct CredentialWire {
            vault_id: VaultId,
            credential_id: CredentialId,
            draft: CredentialDraft,
        }

        let wire = CredentialWire::deserialize(deserializer)?;
        Self::with_id(wire.vault_id, wire.credential_id, wire.draft).map_err(de::Error::custom)
    }
}

/// Non-secret credential metadata with stable vault, credential, and field identities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSummary {
    /// Immutable identity of the containing vault.
    pub vault_id: VaultId,
    /// Immutable identity of this credential.
    pub credential_id: CredentialId,
    /// User-visible credential title.
    pub title: String,
    /// Optional presentation template identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    /// Non-secret descriptors for independently authorizable secret fields.
    pub secret_fields: Vec<SecretFieldSummary>,
    /// User-managed tags.
    pub tags: Vec<String>,
    /// Favorite flag.
    pub favorite: bool,
}

/// Non-secret descriptor for one independently authorizable secret field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretFieldSummary {
    /// Immutable secret-field identity.
    pub secret_field_id: SecretFieldId,
    /// Open provider-neutral semantic role.
    pub role: String,
    /// Optional user-visible label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Provider-neutral secret classification.
    pub kind: SecretFieldKind,
}

impl SecretFieldSummary {
    fn from_field(field: &CredentialField) -> Option<Self> {
        let CredentialFieldValue::Secret {
            secret_field_id,
            kind,
            ..
        } = &field.value
        else {
            return None;
        };

        Some(Self {
            secret_field_id: *secret_field_id,
            role: field.role.clone(),
            label: field.label.clone(),
            kind: *kind,
        })
    }
}

/// Editable encrypted credential content represented as an ordered field collection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialDraft {
    /// User-visible credential title.
    pub title: String,
    /// Optional presentation template identifier, never an authorization identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    /// Ordered extensible credential fields.
    pub fields: Vec<CredentialField>,
    /// User-managed tags.
    pub tags: Vec<String>,
    /// Favorite flag.
    pub favorite: bool,
}

impl CredentialDraft {
    /// Returns only fields that contain secret values.
    pub fn secret_fields(&self) -> impl Iterator<Item = &CredentialField> {
        self.fields
            .iter()
            .filter(|field| matches!(&field.value, CredentialFieldValue::Secret { .. }))
    }
}

/// Human-authored changes to one existing credential.
///
/// Existing Secret Fields are referenced by immutable identity so callers can
/// edit labels, roles, order, and optional replacement material without first
/// reading the saved secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialEdit {
    /// User-visible credential title.
    pub title: String,
    /// Optional presentation template identifier.
    pub template_id: Option<String>,
    /// Complete ordered field list after the edit.
    pub fields: Vec<CredentialFieldEdit>,
    /// User-managed tags.
    pub tags: Vec<String>,
    /// Favorite flag.
    pub favorite: bool,
}

impl CredentialEdit {
    pub(crate) fn materialize(
        self,
        previous: &CredentialDraft,
    ) -> Result<(CredentialDraft, Vec<SecretFieldId>), CredentialValidationError> {
        let mut previous_secrets = HashMap::new();
        let mut allocated_secret_ids = HashSet::new();
        for field in previous.secret_fields() {
            let CredentialFieldValue::Secret {
                secret_field_id,
                kind,
                secret,
            } = &field.value
            else {
                continue;
            };
            if previous_secrets
                .insert(*secret_field_id, (*kind, secret.clone()))
                .is_some()
            {
                return Err(CredentialValidationError::new(
                    "existing secret-field identities must be unique",
                ));
            }
            allocated_secret_ids.insert(*secret_field_id);
        }

        let mut fields = Vec::with_capacity(self.fields.len());
        for field in self.fields {
            let materialized = match field {
                CredentialFieldEdit::Text { role, label, text } => CredentialField {
                    role,
                    label,
                    value: CredentialFieldValue::Text { text },
                },
                CredentialFieldEdit::ExistingSecret {
                    role,
                    label,
                    secret_field_id,
                    replacement,
                } => {
                    let Some((kind, saved_secret)) = previous_secrets.remove(&secret_field_id)
                    else {
                        return Err(CredentialValidationError::new(
                            "existing secret field must belong to this credential and appear once",
                        ));
                    };
                    CredentialField {
                        role,
                        label,
                        value: CredentialFieldValue::Secret {
                            secret_field_id,
                            kind,
                            secret: replacement.unwrap_or(saved_secret),
                        },
                    }
                }
                CredentialFieldEdit::NewSecret {
                    role,
                    label,
                    kind,
                    secret,
                } => {
                    let secret_field_id = loop {
                        let candidate = SecretFieldId::generate();
                        if allocated_secret_ids.insert(candidate) {
                            break candidate;
                        }
                    };
                    CredentialField {
                        role,
                        label,
                        value: CredentialFieldValue::Secret {
                            secret_field_id,
                            kind,
                            secret,
                        },
                    }
                }
            };
            fields.push(materialized);
        }

        let mut removed_secret_field_ids: Vec<_> = previous_secrets.into_keys().collect();
        removed_secret_field_ids.sort_unstable();
        Ok((
            CredentialDraft {
                title: self.title,
                template_id: self.template_id,
                fields,
                tags: self.tags,
                favorite: self.favorite,
            },
            removed_secret_field_ids,
        ))
    }
}

/// One ordered field change in an existing credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialFieldEdit {
    /// A non-secret text field whose role, label, value, and position may change.
    Text {
        /// Open provider-neutral semantic role.
        role: String,
        /// Optional user-visible label.
        label: Option<String>,
        /// Searchable or presentational text.
        text: String,
    },
    /// An existing Secret Field identified without returning its saved value.
    ExistingSecret {
        /// Open provider-neutral semantic role.
        role: String,
        /// Optional user-visible label.
        label: Option<String>,
        /// Immutable identity of the existing Secret Field.
        secret_field_id: SecretFieldId,
        /// Optional replacement material. `None` preserves the saved secret.
        replacement: Option<SecretBytes>,
    },
    /// A newly added Secret Field that receives a fresh immutable identity.
    NewSecret {
        /// Open provider-neutral semantic role.
        role: String,
        /// Optional user-visible label.
        label: Option<String>,
        /// Provider-neutral classification for the new secret.
        kind: SecretFieldKind,
        /// Initial secret material.
        secret: SecretBytes,
    },
}

/// One ordered field in an extensible credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialField {
    /// Open provider-neutral semantic role, such as `username`, `url`, or `token`.
    pub role: String,
    /// Optional user-visible custom label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Explicitly tagged text or secret value.
    pub value: CredentialFieldValue,
}

impl CredentialField {
    /// Creates a non-secret text field.
    pub fn text(role: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            label: None,
            value: CredentialFieldValue::Text { text: text.into() },
        }
    }

    /// Creates a typed secret field.
    pub fn secret(role: impl Into<String>, kind: SecretFieldKind, secret: SecretBytes) -> Self {
        Self::secret_with_id(role, SecretFieldId::generate(), kind, secret)
    }

    /// Creates a typed secret field with an existing immutable identity.
    pub fn secret_with_id(
        role: impl Into<String>,
        secret_field_id: SecretFieldId,
        kind: SecretFieldKind,
        secret: SecretBytes,
    ) -> Self {
        Self {
            role: role.into(),
            label: None,
            value: CredentialFieldValue::Secret {
                secret_field_id,
                kind,
                secret,
            },
        }
    }

    /// Sets a user-visible custom label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Returns the secret kind, or `None` for a text field.
    #[must_use]
    pub fn secret_kind(&self) -> Option<SecretFieldKind> {
        match &self.value {
            CredentialFieldValue::Text { .. } => None,
            CredentialFieldValue::Secret { kind, .. } => Some(*kind),
        }
    }

    /// Returns the stable secret-field identity, or `None` for a text field.
    #[must_use]
    pub fn secret_field_id(&self) -> Option<SecretFieldId> {
        match &self.value {
            CredentialFieldValue::Text { .. } => None,
            CredentialFieldValue::Secret {
                secret_field_id, ..
            } => Some(*secret_field_id),
        }
    }
}

/// Explicitly tagged value stored by one credential field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CredentialFieldValue {
    /// Searchable or presentational text stored inside the encrypted record.
    Text {
        /// Text value.
        text: String,
    },
    /// Independently authorizable secret bytes with a provider-neutral kind.
    Secret {
        /// Immutable identity used for field-scoped authorization.
        secret_field_id: SecretFieldId,
        /// Provider-neutral secret kind.
        kind: SecretFieldKind,
        /// Secret bytes.
        secret: SecretBytes,
    },
}

/// Error returned when typed credential content cannot be represented by the v1 item model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyCredentialConversionError {
    reason: String,
}

impl LegacyCredentialConversionError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// Returns a non-secret explanation of the incompatible structure.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl Display for LegacyCredentialConversionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "typed credential is not representable by the v1 item model: {}",
            self.reason
        )
    }
}

impl std::error::Error for LegacyCredentialConversionError {}

define_string_enum!(
    CredentialUseCapability,
    "A secret-bearing operation that the Broker may perform for an authorized Consumer.",
    "a supported credential-use capability",
    {
        HttpRequest => "http.request",
        ProcessRun => "process.run",
    }
);

impl CredentialUseCapability {
    /// Returns whether this capability semantically supports the secret kind.
    ///
    /// Concrete requests must still pass Usage Profile, placement, and
    /// authorization validation.
    #[must_use]
    pub const fn supports_secret_kind(self, kind: SecretFieldKind) -> bool {
        match self {
            Self::HttpRequest => matches!(
                kind,
                SecretFieldKind::Password
                    | SecretFieldKind::ApiToken
                    | SecretFieldKind::ApiKey
                    | SecretFieldKind::GenericSecret
            ),
            Self::ProcessRun => matches!(
                kind,
                SecretFieldKind::Password
                    | SecretFieldKind::ApiToken
                    | SecretFieldKind::ApiKey
                    | SecretFieldKind::TotpSeed
                    | SecretFieldKind::PrivateKey
                    | SecretFieldKind::Certificate
                    | SecretFieldKind::GenericSecret
            ),
        }
    }
}

pub(crate) const TEMPLATE_LOGIN: &str = "login";
pub(crate) const TEMPLATE_SECURE_NOTE: &str = "secure-note";
pub(crate) const TEMPLATE_SOFTWARE_LICENSE: &str = "software-license";
pub(crate) const TEMPLATE_CREDIT_CARD: &str = "credit-card";

impl From<VaultItemDraft> for CredentialDraft {
    fn from(draft: VaultItemDraft) -> Self {
        let VaultItemDraft {
            title,
            content,
            tags,
            favorite,
        } = draft;
        let (template_id, fields) = match content {
            VaultItemContent::Login(login) => legacy_login_to_fields(login),
            VaultItemContent::SecureNote(note) => legacy_secure_note_to_fields(note),
            VaultItemContent::SoftwareLicense(license) => {
                legacy_software_license_to_fields(license)
            }
            VaultItemContent::CreditCard(card) => legacy_credit_card_to_fields(card),
        };

        Self {
            title,
            template_id: Some(template_id.to_owned()),
            fields,
            tags,
            favorite,
        }
    }
}

impl TryFrom<CredentialDraft> for VaultItemDraft {
    type Error = LegacyCredentialConversionError;

    fn try_from(draft: CredentialDraft) -> Result<Self, Self::Error> {
        let CredentialDraft {
            title,
            template_id,
            fields,
            tags,
            favorite,
        } = draft;
        let template_id = template_id.ok_or_else(|| {
            LegacyCredentialConversionError::new("missing supported template identifier")
        })?;
        let content = match template_id.as_str() {
            TEMPLATE_LOGIN => fields_to_legacy_login(fields)?,
            TEMPLATE_SECURE_NOTE => fields_to_legacy_secure_note(fields)?,
            TEMPLATE_SOFTWARE_LICENSE => fields_to_legacy_software_license(fields)?,
            TEMPLATE_CREDIT_CARD => fields_to_legacy_credit_card(fields)?,
            _ => {
                return Err(LegacyCredentialConversionError::new(format!(
                    "unsupported template identifier '{template_id}'"
                )))
            }
        };

        Ok(Self {
            title,
            content,
            tags,
            favorite,
        })
    }
}

fn legacy_login_to_fields(login: LoginItem) -> (&'static str, Vec<CredentialField>) {
    let mut fields = Vec::new();
    push_optional_text(&mut fields, "username", login.username);
    push_optional_secret(
        &mut fields,
        "password",
        SecretFieldKind::Password,
        login.password,
    );
    fields.extend(
        login
            .urls
            .into_iter()
            .map(|url| CredentialField::text("url", url)),
    );
    push_optional_text(&mut fields, "notes", login.notes);
    push_optional_secret(
        &mut fields,
        "totp-seed",
        SecretFieldKind::TotpSeed,
        login.totp_secret,
    );
    (TEMPLATE_LOGIN, fields)
}

fn legacy_secure_note_to_fields(note: SecureNoteItem) -> (&'static str, Vec<CredentialField>) {
    (
        TEMPLATE_SECURE_NOTE,
        vec![CredentialField::secret(
            "body",
            SecretFieldKind::GenericSecret,
            SecretBytes::new(note.body.into_bytes()),
        )],
    )
}

fn legacy_software_license_to_fields(
    license: SoftwareLicenseItem,
) -> (&'static str, Vec<CredentialField>) {
    let mut fields = Vec::new();
    push_optional_text(&mut fields, "product", license.product);
    push_optional_secret(
        &mut fields,
        "license-key",
        SecretFieldKind::GenericSecret,
        license.license_key,
    );
    push_optional_text(&mut fields, "licensed-to", license.licensed_to);
    push_optional_text(&mut fields, "notes", license.notes);
    (TEMPLATE_SOFTWARE_LICENSE, fields)
}

fn legacy_credit_card_to_fields(card: CreditCardItem) -> (&'static str, Vec<CredentialField>) {
    let mut fields = Vec::new();
    push_optional_text(&mut fields, "cardholder-name", card.cardholder_name);
    push_optional_secret(
        &mut fields,
        "number",
        SecretFieldKind::GenericSecret,
        card.number,
    );
    push_optional_text(
        &mut fields,
        "expiry-month",
        card.expiry_month.map(|month| month.to_string()),
    );
    push_optional_text(
        &mut fields,
        "expiry-year",
        card.expiry_year.map(|year| year.to_string()),
    );
    push_optional_secret(
        &mut fields,
        "verification-code",
        SecretFieldKind::GenericSecret,
        card.verification_code,
    );
    push_optional_text(&mut fields, "notes", card.notes);
    (TEMPLATE_CREDIT_CARD, fields)
}

fn push_optional_text(
    fields: &mut Vec<CredentialField>,
    role: &'static str,
    value: Option<String>,
) {
    if let Some(value) = value {
        fields.push(CredentialField::text(role, value));
    }
}

fn push_optional_secret(
    fields: &mut Vec<CredentialField>,
    role: &'static str,
    kind: SecretFieldKind,
    value: Option<SecretBytes>,
) {
    if let Some(value) = value {
        fields.push(CredentialField::secret(role, kind, value));
    }
}

fn fields_to_legacy_login(
    fields: Vec<CredentialField>,
) -> Result<VaultItemContent, LegacyCredentialConversionError> {
    let mut username = None;
    let mut password = None;
    let mut urls = Vec::new();
    let mut notes = None;
    let mut totp_secret = None;

    for field in fields {
        let (role, value) = legacy_field_parts(field)?;
        match role.as_str() {
            "username" => set_once(&mut username, expect_text(&role, value)?, &role)?,
            "password" => set_once(
                &mut password,
                expect_secret(&role, value, SecretFieldKind::Password)?,
                &role,
            )?,
            "url" => urls.push(expect_text(&role, value)?),
            "notes" => set_once(&mut notes, expect_text(&role, value)?, &role)?,
            "totp-seed" => set_once(
                &mut totp_secret,
                expect_secret(&role, value, SecretFieldKind::TotpSeed)?,
                &role,
            )?,
            _ => return Err(unsupported_legacy_field(&role)),
        }
    }

    Ok(VaultItemContent::Login(LoginItem {
        username,
        password,
        urls,
        notes,
        totp_secret,
    }))
}

fn fields_to_legacy_secure_note(
    fields: Vec<CredentialField>,
) -> Result<VaultItemContent, LegacyCredentialConversionError> {
    let mut body = None;
    for field in fields {
        let (role, value) = legacy_field_parts(field)?;
        match role.as_str() {
            "body" => {
                let secret = expect_secret(&role, value, SecretFieldKind::GenericSecret)?;
                set_once(&mut body, secret_to_utf8(&role, &secret)?, &role)?;
            }
            _ => return Err(unsupported_legacy_field(&role)),
        }
    }
    let body =
        body.ok_or_else(|| LegacyCredentialConversionError::new("missing required 'body' field"))?;
    Ok(VaultItemContent::SecureNote(SecureNoteItem { body }))
}

fn fields_to_legacy_software_license(
    fields: Vec<CredentialField>,
) -> Result<VaultItemContent, LegacyCredentialConversionError> {
    let mut product = None;
    let mut license_key = None;
    let mut licensed_to = None;
    let mut notes = None;

    for field in fields {
        let (role, value) = legacy_field_parts(field)?;
        match role.as_str() {
            "product" => set_once(&mut product, expect_text(&role, value)?, &role)?,
            "license-key" => set_once(
                &mut license_key,
                expect_secret(&role, value, SecretFieldKind::GenericSecret)?,
                &role,
            )?,
            "licensed-to" => set_once(&mut licensed_to, expect_text(&role, value)?, &role)?,
            "notes" => set_once(&mut notes, expect_text(&role, value)?, &role)?,
            _ => return Err(unsupported_legacy_field(&role)),
        }
    }

    Ok(VaultItemContent::SoftwareLicense(SoftwareLicenseItem {
        product,
        license_key,
        licensed_to,
        notes,
    }))
}

fn fields_to_legacy_credit_card(
    fields: Vec<CredentialField>,
) -> Result<VaultItemContent, LegacyCredentialConversionError> {
    let mut cardholder_name = None;
    let mut number = None;
    let mut expiry_month = None;
    let mut expiry_year = None;
    let mut verification_code = None;
    let mut notes = None;

    for field in fields {
        let (role, value) = legacy_field_parts(field)?;
        match role.as_str() {
            "cardholder-name" => set_once(&mut cardholder_name, expect_text(&role, value)?, &role)?,
            "number" => set_once(
                &mut number,
                expect_secret(&role, value, SecretFieldKind::GenericSecret)?,
                &role,
            )?,
            "expiry-month" => {
                let value = parse_numeric_field::<u8>(&role, expect_text(&role, value)?)?;
                set_once(&mut expiry_month, value, &role)?;
            }
            "expiry-year" => {
                let value = parse_numeric_field::<u16>(&role, expect_text(&role, value)?)?;
                set_once(&mut expiry_year, value, &role)?;
            }
            "verification-code" => set_once(
                &mut verification_code,
                expect_secret(&role, value, SecretFieldKind::GenericSecret)?,
                &role,
            )?,
            "notes" => set_once(&mut notes, expect_text(&role, value)?, &role)?,
            _ => return Err(unsupported_legacy_field(&role)),
        }
    }

    Ok(VaultItemContent::CreditCard(CreditCardItem {
        cardholder_name,
        number,
        expiry_month,
        expiry_year,
        verification_code,
        notes,
    }))
}

fn legacy_field_parts(
    field: CredentialField,
) -> Result<(String, CredentialFieldValue), LegacyCredentialConversionError> {
    if field.label.is_some() {
        return Err(LegacyCredentialConversionError::new(format!(
            "field '{}' has a custom label",
            field.role
        )));
    }
    Ok((field.role, field.value))
}

fn expect_text(
    role: &str,
    value: CredentialFieldValue,
) -> Result<String, LegacyCredentialConversionError> {
    match value {
        CredentialFieldValue::Text { text } => Ok(text),
        CredentialFieldValue::Secret { .. } => Err(LegacyCredentialConversionError::new(format!(
            "field '{role}' must contain text"
        ))),
    }
}

fn expect_secret(
    role: &str,
    value: CredentialFieldValue,
    expected_kind: SecretFieldKind,
) -> Result<SecretBytes, LegacyCredentialConversionError> {
    match value {
        CredentialFieldValue::Secret { kind, secret, .. } if kind == expected_kind => Ok(secret),
        CredentialFieldValue::Secret { kind, .. } => Err(LegacyCredentialConversionError::new(
            format!("field '{role}' has secret kind '{kind}', expected '{expected_kind}'"),
        )),
        CredentialFieldValue::Text { .. } => Err(LegacyCredentialConversionError::new(format!(
            "field '{role}' must contain a secret"
        ))),
    }
}

fn set_once<T>(
    target: &mut Option<T>,
    value: T,
    role: &str,
) -> Result<(), LegacyCredentialConversionError> {
    if target.is_some() {
        return Err(LegacyCredentialConversionError::new(format!(
            "field '{role}' occurs more than once"
        )));
    }
    *target = Some(value);
    Ok(())
}

fn secret_to_utf8(
    role: &str,
    secret: &SecretBytes,
) -> Result<String, LegacyCredentialConversionError> {
    String::from_utf8(secret.expose().to_vec()).map_err(|_| {
        LegacyCredentialConversionError::new(format!("field '{role}' is not valid UTF-8"))
    })
}

fn parse_numeric_field<T>(role: &str, value: String) -> Result<T, LegacyCredentialConversionError>
where
    T: FromStr,
{
    value.parse().map_err(|_| {
        LegacyCredentialConversionError::new(format!(
            "field '{role}' does not contain a valid number"
        ))
    })
}

fn unsupported_legacy_field(role: &str) -> LegacyCredentialConversionError {
    LegacyCredentialConversionError::new(format!("unsupported field role '{role}'"))
}

#[cfg(test)]
mod tests {
    use std::fmt::{Debug, Display};
    use std::str::FromStr;

    use serde::de::DeserializeOwned;
    use serde::Serialize;

    use crate::{
        CredentialId, CreditCardItem, LoginItem, SecretBytes, SecretFieldId, SecureNoteItem,
        SoftwareLicenseItem, VaultId, VaultItemContent, VaultItemDraft,
    };

    use super::{
        built_in_credential_template, Credential, CredentialDraft, CredentialField,
        CredentialFieldValue, CredentialUseCapability, SecretFieldKind,
        BUILT_IN_CREDENTIAL_TEMPLATES,
    };

    #[test]
    fn built_in_templates_cover_required_human_and_developer_credentials() {
        let expected = [
            ("login", "password", SecretFieldKind::Password, false),
            ("api-token", "token", SecretFieldKind::ApiToken, true),
            ("api-key", "api-key", SecretFieldKind::ApiKey, true),
            ("ssh-key", "private-key", SecretFieldKind::PrivateKey, true),
            (
                "certificate",
                "certificate",
                SecretFieldKind::Certificate,
                true,
            ),
            ("secure-note", "body", SecretFieldKind::GenericSecret, false),
            ("custom", "secret", SecretFieldKind::GenericSecret, true),
        ];

        assert_eq!(BUILT_IN_CREDENTIAL_TEMPLATES.len(), expected.len());
        let unique_ids = BUILT_IN_CREDENTIAL_TEMPLATES
            .iter()
            .map(|template| template.id)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(unique_ids.len(), expected.len());
        for (id, role, kind, required) in expected {
            let template = built_in_credential_template(id).expect("required template");
            assert_eq!(template.primary_secret_role, role);
            assert_eq!(template.primary_secret_kind, kind);
            assert_eq!(template.primary_secret_required, required);
        }
        assert!(built_in_credential_template("github-token").is_none());
        assert!(built_in_credential_template("API-token").is_none());
    }

    #[test]
    fn simple_api_token_template_requires_only_title_and_primary_secret() {
        let template = built_in_credential_template("api-token").expect("API token template");

        assert!(template.primary_secret_required);
        assert_eq!(template.primary_secret_role, "token");
        assert_eq!(template.primary_secret_kind, SecretFieldKind::ApiToken);
        assert_eq!(template.optional_text_roles, ["expiry", "notes"]);
    }

    #[test]
    fn secret_field_kinds_have_canonical_provider_neutral_serialization() {
        let expected = [
            (SecretFieldKind::Password, "password"),
            (SecretFieldKind::ApiToken, "api-token"),
            (SecretFieldKind::ApiKey, "api-key"),
            (SecretFieldKind::TotpSeed, "totp-seed"),
            (SecretFieldKind::PrivateKey, "private-key"),
            (SecretFieldKind::Certificate, "certificate"),
            (SecretFieldKind::GenericSecret, "generic-secret"),
        ];

        assert_eq!(SecretFieldKind::ALL.len(), expected.len());
        for (kind, serialized) in expected {
            assert!(SecretFieldKind::ALL.contains(&kind));
            assert_canonical_round_trip(kind, serialized);
        }
    }

    #[test]
    fn credential_use_capabilities_have_canonical_serialization() {
        let expected = [
            (CredentialUseCapability::HttpRequest, "http.request"),
            (CredentialUseCapability::ProcessRun, "process.run"),
        ];

        assert_eq!(CredentialUseCapability::ALL.len(), expected.len());
        for (capability, serialized) in expected {
            assert!(CredentialUseCapability::ALL.contains(&capability));
            assert_canonical_round_trip(capability, serialized);
        }
    }

    #[test]
    fn unknown_kinds_and_capabilities_fail_closed() {
        for value in [
            "",
            "github-token",
            "bearer-token",
            "api_token",
            "API-token",
            "api-token ",
        ] {
            assert!(
                value.parse::<SecretFieldKind>().is_err(),
                "accepted unknown secret field kind: {value}"
            );
        }

        for value in [
            "",
            "secret.get",
            "credential.search",
            "http_request",
            "HTTP.REQUEST",
            "process.run ",
        ] {
            assert!(
                value.parse::<CredentialUseCapability>().is_err(),
                "accepted unknown credential-use capability: {value}"
            );
        }

        assert!(serde_json::from_str::<SecretFieldKind>("null").is_err());
        assert!(serde_json::from_str::<CredentialUseCapability>("{}").is_err());
    }

    #[test]
    fn capability_compatibility_matrix_is_exhaustive_and_fail_closed() {
        let http_request_kinds = [
            SecretFieldKind::Password,
            SecretFieldKind::ApiToken,
            SecretFieldKind::ApiKey,
            SecretFieldKind::GenericSecret,
        ];

        for kind in SecretFieldKind::ALL.iter().copied() {
            assert_eq!(
                CredentialUseCapability::HttpRequest.supports_secret_kind(kind),
                http_request_kinds.contains(&kind),
                "unexpected http.request compatibility for {kind}"
            );
            assert!(
                CredentialUseCapability::ProcessRun.supports_secret_kind(kind),
                "process.run should support explicit compatibility delivery for {kind}"
            );
        }
    }

    #[test]
    fn extensible_credential_fields_round_trip_without_provider_core_types() {
        let credential = CredentialDraft {
            title: "GitHub automation".to_owned(),
            template_id: Some("github-cli-token".to_owned()),
            fields: vec![
                CredentialField::text("account", "chasechou007"),
                CredentialField::secret(
                    "token",
                    SecretFieldKind::ApiToken,
                    SecretBytes::new(b"synthetic-token".to_vec()),
                )
                .with_label("Personal token"),
            ],
            tags: vec!["development".to_owned()],
            favorite: true,
        };

        let encoded = serde_json::to_value(&credential).expect("serialize typed credential");
        assert_eq!(encoded["template_id"], "github-cli-token");
        assert_eq!(encoded["fields"][0]["role"], "account");
        assert_eq!(encoded["fields"][0]["value"]["type"], "text");
        assert_eq!(encoded["fields"][1]["value"]["type"], "secret");
        assert_eq!(encoded["fields"][1]["value"]["kind"], "api-token");
        assert_eq!(
            encoded["fields"][1]["value"]["secret_field_id"],
            credential.fields[1]
                .secret_field_id()
                .expect("secret field ID")
                .to_string()
        );
        assert_eq!(credential.fields[0].secret_field_id(), None);
        assert_eq!(credential.secret_fields().count(), 1);

        let decoded: CredentialDraft =
            serde_json::from_value(encoded).expect("deserialize typed credential");
        assert_eq!(decoded, credential);
    }

    #[test]
    fn credential_summary_preserves_identities_and_excludes_field_values() {
        let vault_id = VaultId::generate();
        let credential_id = CredentialId::generate();
        let secret_field_id = SecretFieldId::generate();
        let mut credential = Credential::with_id(
            vault_id,
            credential_id,
            CredentialDraft {
                title: "Automation token".to_owned(),
                template_id: Some("api-token".to_owned()),
                fields: vec![
                    CredentialField::text("account", "private-account"),
                    CredentialField::secret_with_id(
                        "token",
                        secret_field_id,
                        SecretFieldKind::ApiToken,
                        SecretBytes::new(b"first-secret-marker".to_vec()),
                    ),
                ],
                tags: vec!["development".to_owned()],
                favorite: false,
            },
        )
        .expect("create credential");

        credential.draft_mut().title = "Renamed token".to_owned();
        credential.draft_mut().fields[1].label = Some("Updated label".to_owned());
        let CredentialFieldValue::Secret { secret, .. } =
            &mut credential.draft_mut().fields[1].value
        else {
            panic!("expected secret field");
        };
        *secret = SecretBytes::new(b"second-secret-marker".to_vec());

        let summary = credential.summary().expect("summarize credential");
        assert_eq!(summary.vault_id, vault_id);
        assert_eq!(summary.credential_id, credential_id);
        assert_eq!(summary.secret_fields.len(), 1);
        assert_eq!(summary.secret_fields[0].secret_field_id, secret_field_id);
        assert_eq!(
            summary.secret_fields[0].label.as_deref(),
            Some("Updated label")
        );

        let encoded = serde_json::to_string(&summary).expect("serialize credential summary");
        assert!(!encoded.contains("private-account"));
        assert!(!encoded.contains("first-secret-marker"));
        assert!(!encoded.contains("second-secret-marker"));
    }

    #[test]
    fn credential_parsing_rejects_malformed_identity_kind_and_structure() {
        let first_secret_id = SecretFieldId::generate();
        let credential = Credential::with_id(
            VaultId::generate(),
            CredentialId::generate(),
            CredentialDraft {
                title: "Parser fixture".to_owned(),
                template_id: None,
                fields: vec![
                    CredentialField::secret_with_id(
                        "token",
                        first_secret_id,
                        SecretFieldKind::ApiToken,
                        SecretBytes::new(b"token-marker".to_vec()),
                    ),
                    CredentialField::secret_with_id(
                        "key",
                        SecretFieldId::generate(),
                        SecretFieldKind::ApiKey,
                        SecretBytes::new(b"key-marker".to_vec()),
                    ),
                ],
                tags: Vec::new(),
                favorite: false,
            },
        )
        .expect("create parser fixture");
        let encoded = serde_json::to_value(&credential).expect("serialize credential");

        let mut duplicate_field_id = encoded.clone();
        duplicate_field_id["draft"]["fields"][1]["value"]["secret_field_id"] =
            serde_json::Value::String(first_secret_id.to_string());
        assert!(serde_json::from_value::<Credential>(duplicate_field_id).is_err());

        let mut malformed_vault_id = encoded.clone();
        malformed_vault_id["vault_id"] =
            serde_json::Value::String(credential.vault_id().to_string().to_ascii_uppercase());
        assert!(serde_json::from_value::<Credential>(malformed_vault_id).is_err());

        let mut wrong_credential_id_kind = encoded.clone();
        wrong_credential_id_kind["credential_id"] =
            serde_json::Value::String(credential.vault_id().to_string());
        assert!(serde_json::from_value::<Credential>(wrong_credential_id_kind).is_err());

        let mut unknown_secret_kind = encoded.clone();
        unknown_secret_kind["draft"]["fields"][0]["value"]["kind"] =
            serde_json::Value::String("github-token".to_owned());
        assert!(serde_json::from_value::<Credential>(unknown_secret_kind).is_err());

        let mut unknown_value_type = encoded.clone();
        unknown_value_type["draft"]["fields"][0]["value"]["type"] =
            serde_json::Value::String("opaque".to_owned());
        assert!(serde_json::from_value::<Credential>(unknown_value_type).is_err());

        let mut unknown_field = encoded;
        unknown_field["unexpected"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<Credential>(unknown_field).is_err());
        assert!(serde_json::from_str::<CredentialUseCapability>("\"secret.get\"").is_err());
    }

    #[test]
    fn credential_construction_rejects_duplicate_secret_field_identities() {
        let duplicate_id = SecretFieldId::generate();
        let error = Credential::new(
            VaultId::generate(),
            CredentialDraft {
                title: "Duplicate".to_owned(),
                template_id: None,
                fields: vec![
                    CredentialField::secret_with_id(
                        "first",
                        duplicate_id,
                        SecretFieldKind::ApiToken,
                        SecretBytes::new(b"first".to_vec()),
                    ),
                    CredentialField::secret_with_id(
                        "second",
                        duplicate_id,
                        SecretFieldKind::ApiKey,
                        SecretBytes::new(b"second".to_vec()),
                    ),
                ],
                tags: Vec::new(),
                favorite: false,
            },
        )
        .expect_err("duplicate secret field identities");

        assert!(error.reason().contains("unique"));
    }

    #[test]
    fn every_v1_item_draft_round_trips_through_extensible_fields() {
        let drafts = vec![
            VaultItemDraft {
                title: "Login".to_owned(),
                content: VaultItemContent::Login(LoginItem {
                    username: Some("alice".to_owned()),
                    password: Some(SecretBytes::new(b"password".to_vec())),
                    urls: vec![
                        "https://example.com".to_owned(),
                        "https://login.example.com".to_owned(),
                    ],
                    notes: Some("login notes".to_owned()),
                    totp_secret: Some(SecretBytes::new(b"TOTPSEED".to_vec())),
                }),
                tags: vec!["work".to_owned()],
                favorite: true,
            },
            VaultItemDraft {
                title: "Secure note".to_owned(),
                content: VaultItemContent::SecureNote(SecureNoteItem {
                    body: "private body".to_owned(),
                }),
                tags: vec!["private".to_owned()],
                favorite: false,
            },
            VaultItemDraft {
                title: "License".to_owned(),
                content: VaultItemContent::SoftwareLicense(SoftwareLicenseItem {
                    product: Some("Example Pro".to_owned()),
                    license_key: Some(SecretBytes::new(b"LICENSE-KEY".to_vec())),
                    licensed_to: Some("Alice".to_owned()),
                    notes: Some("renew yearly".to_owned()),
                }),
                tags: vec!["software".to_owned()],
                favorite: false,
            },
            VaultItemDraft {
                title: "Card".to_owned(),
                content: VaultItemContent::CreditCard(CreditCardItem {
                    cardholder_name: Some("Alice".to_owned()),
                    number: Some(SecretBytes::new(b"4111111111111111".to_vec())),
                    expiry_month: Some(9),
                    expiry_year: Some(2030),
                    verification_code: Some(SecretBytes::new(b"123".to_vec())),
                    notes: Some("personal".to_owned()),
                }),
                tags: vec!["payment".to_owned()],
                favorite: true,
            },
        ];

        for legacy in drafts {
            let typed = CredentialDraft::from(legacy.clone());
            let restored = VaultItemDraft::try_from(typed).expect("restore v1 item draft");
            assert_eq!(restored, legacy);
        }
    }

    #[test]
    fn v1_conversion_rejects_lossy_custom_fields_and_templates() {
        let custom_template = CredentialDraft {
            title: "Token".to_owned(),
            template_id: Some("api-token".to_owned()),
            fields: vec![CredentialField::secret(
                "token",
                SecretFieldKind::ApiToken,
                SecretBytes::new(b"token".to_vec()),
            )],
            tags: Vec::new(),
            favorite: false,
        };
        let error = VaultItemDraft::try_from(custom_template).expect_err("unsupported v1 template");
        assert!(error.reason().contains("unsupported template"));

        let custom_field = CredentialDraft {
            title: "Login".to_owned(),
            template_id: Some("login".to_owned()),
            fields: vec![
                CredentialField::text("username", "alice"),
                CredentialField::text("tenant", "example"),
            ],
            tags: Vec::new(),
            favorite: false,
        };
        let error = VaultItemDraft::try_from(custom_field).expect_err("unsupported v1 field");
        assert!(error.reason().contains("unsupported field role"));
    }

    fn assert_canonical_round_trip<T>(value: T, expected: &str)
    where
        T: Copy + Debug + DeserializeOwned + Display + Eq + FromStr + Serialize,
        <T as FromStr>::Err: Debug,
    {
        assert_eq!(value.to_string(), expected);

        let encoded = serde_json::to_string(&value).expect("serialize credential-model value");
        assert_eq!(encoded, format!("\"{expected}\""));
        assert_eq!(
            serde_json::from_str::<T>(&encoded).expect("deserialize credential-model value"),
            value
        );
        assert_eq!(
            expected.parse::<T>().expect("parse credential-model value"),
            value
        );
    }
}
