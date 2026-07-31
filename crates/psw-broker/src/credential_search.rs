use std::fmt::{Debug, Display, Formatter};

use psw_core::{CredentialSummary, SecretFieldId, SecretFieldKind, VaultId};
use zeroize::Zeroize;

use crate::protocol::BrokerErrorCode;
use crate::state_model::{AuthorizationTarget, CapabilityName, CredentialFieldScope};

/// Maximum UTF-8 byte length accepted for one authorized metadata query.
pub const MAX_CREDENTIAL_SEARCH_QUERY_BYTES: usize = 256;

/// Bounded in-memory query for already-authorized credential metadata.
pub struct BrokerCredentialSearchQuery {
    normalized: String,
}

impl BrokerCredentialSearchQuery {
    /// Creates a case-insensitive query without retaining surrounding whitespace.
    pub fn new(mut text: String) -> Result<Self, BrokerCredentialSearchError> {
        let invalid = text.trim().len() > MAX_CREDENTIAL_SEARCH_QUERY_BYTES
            || text.trim().chars().any(char::is_control);
        if invalid {
            text.zeroize();
            return Err(BrokerCredentialSearchError::InvalidQuery);
        }
        let normalized = text.trim().to_lowercase();
        text.zeroize();
        Ok(Self { normalized })
    }

    /// Returns whether this query selects the exact authorized credential
    /// without an additional text filter.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.normalized.is_empty()
    }
}

impl Debug for BrokerCredentialSearchQuery {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerCredentialSearchQuery")
            .field("text", &"<redacted>")
            .finish()
    }
}

impl Drop for BrokerCredentialSearchQuery {
    fn drop(&mut self) {
        self.normalized.zeroize();
    }
}

/// Non-secret descriptor for the one Secret Field covered by a search grant.
#[derive(Eq, PartialEq)]
pub struct BrokerAuthorizedFieldMetadata {
    secret_field_id: SecretFieldId,
    role: String,
    label: Option<String>,
    kind: SecretFieldKind,
}

impl BrokerAuthorizedFieldMetadata {
    /// Returns the stable authorized Secret Field identity.
    #[must_use]
    pub const fn secret_field_id(&self) -> SecretFieldId {
        self.secret_field_id
    }

    /// Returns the provider-neutral field role.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Returns the optional user-visible field label.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Returns the authoritative provider-neutral Secret Field kind.
    #[must_use]
    pub const fn kind(&self) -> SecretFieldKind {
        self.kind
    }
}

impl Debug for BrokerAuthorizedFieldMetadata {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerAuthorizedFieldMetadata")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Drop for BrokerAuthorizedFieldMetadata {
    fn drop(&mut self) {
        self.role.zeroize();
        if let Some(label) = &mut self.label {
            label.zeroize();
        }
    }
}

/// Minimum metadata returned for one already-authorized credential.
#[derive(Eq, PartialEq)]
pub struct BrokerCredentialMetadata {
    vault_id: VaultId,
    credential_id: psw_core::CredentialId,
    title: String,
    authorized_field: BrokerAuthorizedFieldMetadata,
}

impl BrokerCredentialMetadata {
    /// Returns the stable vault identity.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Returns the stable credential identity.
    #[must_use]
    pub const fn credential_id(&self) -> psw_core::CredentialId {
        self.credential_id
    }

    /// Returns the authorized credential title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns only the Secret Field descriptor covered by the grant.
    #[must_use]
    pub const fn authorized_field(&self) -> &BrokerAuthorizedFieldMetadata {
        &self.authorized_field
    }
}

impl Debug for BrokerCredentialMetadata {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerCredentialMetadata")
            .field("authorized_field", &self.authorized_field)
            .finish_non_exhaustive()
    }
}

impl Drop for BrokerCredentialMetadata {
    fn drop(&mut self) {
        self.title.zeroize();
    }
}

/// Zero-or-one result from searching one exact authorized credential scope.
#[derive(Eq, PartialEq)]
pub struct BrokerCredentialSearchResult {
    credential: Option<BrokerCredentialMetadata>,
}

impl BrokerCredentialSearchResult {
    /// Returns matching minimum metadata, if the authorized credential matched.
    #[must_use]
    pub const fn credential(&self) -> Option<&BrokerCredentialMetadata> {
        self.credential.as_ref()
    }
}

impl Debug for BrokerCredentialSearchResult {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerCredentialSearchResult")
            .field("matched", &self.credential.is_some())
            .finish()
    }
}

/// Sanitized authorized metadata-search failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerCredentialSearchError {
    /// The query is unbounded or contains control characters.
    InvalidQuery,
    /// The target does not name `credential.search` version 1.
    UnsupportedCapability,
    /// Authenticated vault metadata does not match the authorized field scope.
    ScopeUnavailable,
}

impl BrokerCredentialSearchError {
    /// Returns the stable machine-facing error category.
    #[must_use]
    pub const fn broker_error_code(self) -> BrokerErrorCode {
        match self {
            Self::InvalidQuery => BrokerErrorCode::InvalidRequest,
            Self::UnsupportedCapability => BrokerErrorCode::UnsupportedCapability,
            Self::ScopeUnavailable => BrokerErrorCode::AccessDenied,
        }
    }
}

impl Display for BrokerCredentialSearchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidQuery => formatter.write_str("credential search query is invalid"),
            Self::UnsupportedCapability => {
                formatter.write_str("credential search capability is unsupported")
            }
            Self::ScopeUnavailable => formatter.write_str("credential search scope is unavailable"),
        }
    }
}

impl std::error::Error for BrokerCredentialSearchError {}

pub(crate) struct BrokerCredentialSearchManager;

impl BrokerCredentialSearchManager {
    pub(crate) fn validate_target(
        target: AuthorizationTarget,
    ) -> Result<(), BrokerCredentialSearchError> {
        let capability = target.capability();
        if capability.name() != CapabilityName::CredentialSearch || capability.version() != 1 {
            return Err(BrokerCredentialSearchError::UnsupportedCapability);
        }
        Ok(())
    }

    pub(crate) fn project(
        query: &BrokerCredentialSearchQuery,
        target: AuthorizationTarget,
        expected_kind: SecretFieldKind,
        summary: Option<CredentialSummary>,
    ) -> Result<BrokerCredentialSearchResult, BrokerCredentialSearchError> {
        Self::validate_target(target)?;
        let credential =
            Self::project_exact(target.field_scope(), expected_kind, summary)?.filter(|metadata| {
                query.is_empty()
                    || contains_normalized(&metadata.title, &query.normalized)
                    || contains_normalized(&metadata.authorized_field.role, &query.normalized)
                    || metadata
                        .authorized_field
                        .label
                        .as_deref()
                        .is_some_and(|label| contains_normalized(label, &query.normalized))
            });
        Ok(BrokerCredentialSearchResult { credential })
    }

    pub(crate) fn project_exact(
        field_scope: CredentialFieldScope,
        expected_kind: SecretFieldKind,
        summary: Option<CredentialSummary>,
    ) -> Result<Option<BrokerCredentialMetadata>, BrokerCredentialSearchError> {
        let Some(summary) = summary else {
            return Ok(None);
        };
        if summary.vault_id != field_scope.vault_id()
            || summary.credential_id != field_scope.credential_id()
        {
            return Err(BrokerCredentialSearchError::ScopeUnavailable);
        }
        let mut matching_fields = summary
            .secret_fields
            .into_iter()
            .filter(|field| field.secret_field_id == field_scope.secret_field_id());
        let Some(field) = matching_fields.next() else {
            return Err(BrokerCredentialSearchError::ScopeUnavailable);
        };
        if matching_fields.next().is_some() || field.kind != expected_kind {
            return Err(BrokerCredentialSearchError::ScopeUnavailable);
        }
        let authorized_field = BrokerAuthorizedFieldMetadata {
            secret_field_id: field.secret_field_id,
            role: field.role,
            label: field.label,
            kind: field.kind,
        };
        Ok(Some(BrokerCredentialMetadata {
            vault_id: summary.vault_id,
            credential_id: summary.credential_id,
            title: summary.title,
            authorized_field,
        }))
    }
}

fn contains_normalized(value: &str, normalized_query: &str) -> bool {
    value.to_lowercase().contains(normalized_query)
}

#[cfg(test)]
mod tests {
    use psw_core::{CredentialId, SecretFieldSummary};

    use super::*;
    use crate::state_model::{AuthorizationTarget, Capability, ConsumerId, CredentialFieldScope};

    struct Fixture {
        target: AuthorizationTarget,
        expected_kind: SecretFieldKind,
        summary: CredentialSummary,
        other_field_id: SecretFieldId,
    }

    fn fixture() -> Fixture {
        let vault_id = VaultId::generate();
        let credential_id = CredentialId::generate();
        let authorized_field_id = SecretFieldId::generate();
        let other_field_id = SecretFieldId::generate();
        Fixture {
            target: AuthorizationTarget::new(
                ConsumerId::generate(),
                CredentialFieldScope::new(vault_id, credential_id, authorized_field_id),
                Capability::v1(CapabilityName::CredentialSearch),
            ),
            expected_kind: SecretFieldKind::ApiToken,
            summary: CredentialSummary {
                vault_id,
                credential_id,
                title: "Production API".to_owned(),
                template_id: Some("private-template".to_owned()),
                secret_fields: vec![
                    SecretFieldSummary {
                        secret_field_id: authorized_field_id,
                        role: "token".to_owned(),
                        label: Some("Deployment token".to_owned()),
                        kind: SecretFieldKind::ApiToken,
                    },
                    SecretFieldSummary {
                        secret_field_id: other_field_id,
                        role: "password".to_owned(),
                        label: Some("Hidden password label".to_owned()),
                        kind: SecretFieldKind::Password,
                    },
                ],
                tags: vec!["private-tag".to_owned()],
                favorite: true,
            },
            other_field_id,
        }
    }

    #[test]
    fn projection_contains_only_title_and_the_exact_authorized_field() {
        let fixture = fixture();
        let result = BrokerCredentialSearchManager::project(
            &BrokerCredentialSearchQuery::new("deployment".to_owned()).expect("query"),
            fixture.target,
            fixture.expected_kind,
            Some(fixture.summary),
        )
        .expect("project");
        let credential = result.credential().expect("match");

        assert_eq!(credential.title(), "Production API");
        assert_eq!(
            credential.authorized_field().secret_field_id(),
            fixture.target.field_scope().secret_field_id()
        );
        assert_eq!(credential.authorized_field().role(), "token");
        assert_eq!(
            credential.authorized_field().label(),
            Some("Deployment token")
        );
        assert_eq!(
            credential.authorized_field().kind(),
            SecretFieldKind::ApiToken
        );
        assert_ne!(
            credential.authorized_field().secret_field_id(),
            fixture.other_field_id
        );
    }

    #[test]
    fn query_never_matches_omitted_template_tags_or_other_fields() {
        for query_text in [
            "private-template",
            "private-tag",
            "hidden password",
            "password",
        ] {
            let fixture = fixture();
            let result = BrokerCredentialSearchManager::project(
                &BrokerCredentialSearchQuery::new(query_text.to_owned()).expect("query"),
                fixture.target,
                fixture.expected_kind,
                Some(fixture.summary),
            )
            .expect("project");
            assert!(result.credential().is_none(), "{query_text}");
        }
    }

    #[test]
    fn missing_or_changed_authorized_field_fails_closed() {
        let fixture = fixture();
        assert_eq!(
            BrokerCredentialSearchManager::project(
                &BrokerCredentialSearchQuery::new(String::new()).expect("query"),
                AuthorizationTarget::new(
                    fixture.target.consumer_id(),
                    CredentialFieldScope::new(
                        fixture.target.field_scope().vault_id(),
                        fixture.target.field_scope().credential_id(),
                        SecretFieldId::generate(),
                    ),
                    fixture.target.capability(),
                ),
                fixture.expected_kind,
                Some(fixture.summary.clone()),
            ),
            Err(BrokerCredentialSearchError::ScopeUnavailable)
        );
        assert_eq!(
            BrokerCredentialSearchManager::project(
                &BrokerCredentialSearchQuery::new(String::new()).expect("query"),
                fixture.target,
                SecretFieldKind::Password,
                Some(fixture.summary),
            ),
            Err(BrokerCredentialSearchError::ScopeUnavailable)
        );
    }

    #[test]
    fn query_and_capability_validation_are_bounded_and_fail_closed() {
        assert_eq!(
            BrokerCredentialSearchQuery::new("x".repeat(MAX_CREDENTIAL_SEARCH_QUERY_BYTES + 1))
                .expect_err("oversized query"),
            BrokerCredentialSearchError::InvalidQuery
        );
        assert_eq!(
            BrokerCredentialSearchQuery::new("line\nbreak".to_owned())
                .expect_err("control character"),
            BrokerCredentialSearchError::InvalidQuery
        );
        let fixture = fixture();
        let wrong_capability = AuthorizationTarget::new(
            fixture.target.consumer_id(),
            fixture.target.field_scope(),
            Capability::v1(CapabilityName::HttpRequest),
        );
        assert_eq!(
            BrokerCredentialSearchManager::validate_target(wrong_capability),
            Err(BrokerCredentialSearchError::UnsupportedCapability)
        );
        let future = AuthorizationTarget::new(
            fixture.target.consumer_id(),
            fixture.target.field_scope(),
            Capability::new(CapabilityName::CredentialSearch, 2).expect("future capability"),
        );
        assert_eq!(
            BrokerCredentialSearchManager::validate_target(future),
            Err(BrokerCredentialSearchError::UnsupportedCapability)
        );
    }

    #[test]
    fn debug_output_redacts_query_title_label_and_stable_identities() {
        let fixture = fixture();
        let query =
            BrokerCredentialSearchQuery::new("deployment".to_owned()).expect("search query");
        let target_text = fixture.target.field_scope().credential_id().to_string();
        let result = BrokerCredentialSearchManager::project(
            &query,
            fixture.target,
            fixture.expected_kind,
            Some(fixture.summary),
        )
        .expect("project");
        let rendered = format!("{query:?} {result:?}");

        assert!(!rendered.contains("deployment"));
        assert!(!rendered.contains("Production API"));
        assert!(!rendered.contains("Deployment token"));
        assert!(!rendered.contains(&target_text));
    }
}
