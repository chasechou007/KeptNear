use std::fmt::{Display, Formatter};
use std::str::FromStr;

use crate::state_model::{
    Capability, CapabilityName, DeviceStateValidationError, UsagePlacement, UsageProfileDefinition,
};

const DEFAULT_API_KEY_HEADER_NAME: &str = "X-API-Key";

/// Stable identity of one bundled offline Usage Profile template.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BundledUsageProfileTemplateId {
    /// HTTP Authorization header using the Bearer scheme.
    HttpBearerAuthorization,
    /// HTTP API key in a named header.
    HttpApiKeyHeader,
    /// Child-process environment variable.
    CliEnvironmentVariable,
}

impl BundledUsageProfileTemplateId {
    /// Returns the stable storage and adapter value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HttpBearerAuthorization => "http-bearer-authorization",
            Self::HttpApiKeyHeader => "http-api-key-header",
            Self::CliEnvironmentVariable => "cli-environment-variable",
        }
    }
}

impl Display for BundledUsageProfileTemplateId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for BundledUsageProfileTemplateId {
    type Err = BundledUsageProfileTemplateIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "http-bearer-authorization" => Ok(Self::HttpBearerAuthorization),
            "http-api-key-header" => Ok(Self::HttpApiKeyHeader),
            "cli-environment-variable" => Ok(Self::CliEnvironmentVariable),
            _ => Err(BundledUsageProfileTemplateIdParseError),
        }
    }
}

/// Error returned for an unknown bundled Usage Profile template identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundledUsageProfileTemplateIdParseError;

impl Display for BundledUsageProfileTemplateIdParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("unknown bundled Usage Profile template")
    }
}

impl std::error::Error for BundledUsageProfileTemplateIdParseError {}

/// Optional technical field required to instantiate a bundled template.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageProfileTemplateTechnicalField {
    /// The template has no configurable technical field.
    None,
    /// A bounded HTTP header name, with an offline suggested value.
    HttpHeaderName {
        /// Suggested header name used when the user does not override it.
        suggested_value: &'static str,
    },
    /// A required child-process environment-variable name.
    EnvironmentVariableName,
}

/// Stable identity of one recognized offline Usage Profile recommendation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BundledUsageProfileRecommendationId {
    /// GitHub CLI using its documented child environment variable.
    GitHubCli,
    /// GitLab CLI using its documented child environment variable.
    GitLabCli,
}

impl BundledUsageProfileRecommendationId {
    /// Returns the stable adapter and localization value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GitHubCli => "github-cli",
            Self::GitLabCli => "gitlab-cli",
        }
    }
}

/// One exact, non-authoritative recommendation for a recognized local tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundledUsageProfileRecommendation {
    id: BundledUsageProfileRecommendationId,
    template_id: BundledUsageProfileTemplateId,
    technical_name: &'static str,
}

impl BundledUsageProfileRecommendation {
    const fn new(
        id: BundledUsageProfileRecommendationId,
        template_id: BundledUsageProfileTemplateId,
        technical_name: &'static str,
    ) -> Self {
        Self {
            id,
            template_id,
            technical_name,
        }
    }

    /// Returns the stable recommendation identity.
    #[must_use]
    pub const fn id(self) -> BundledUsageProfileRecommendationId {
        self.id
    }

    /// Returns the provider-neutral template selected by the recommendation.
    #[must_use]
    pub const fn template_id(self) -> BundledUsageProfileTemplateId {
        self.template_id
    }

    /// Returns the non-secret technical name proposed for that template.
    #[must_use]
    pub const fn technical_name(self) -> &'static str {
        self.technical_name
    }
}

/// One immutable Usage Profile template compiled into KeptNear.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundledUsageProfileTemplate {
    id: BundledUsageProfileTemplateId,
    capability: Capability,
    technical_field: UsageProfileTemplateTechnicalField,
}

impl BundledUsageProfileTemplate {
    const fn new(
        id: BundledUsageProfileTemplateId,
        capability: Capability,
        technical_field: UsageProfileTemplateTechnicalField,
    ) -> Self {
        Self {
            id,
            capability,
            technical_field,
        }
    }

    /// Returns the stable bundled template identity.
    #[must_use]
    pub const fn id(self) -> BundledUsageProfileTemplateId {
        self.id
    }

    /// Returns the operation capability produced by this template.
    #[must_use]
    pub const fn capability(self) -> Capability {
        self.capability
    }

    /// Returns the optional advanced technical field.
    #[must_use]
    pub const fn technical_field(self) -> UsageProfileTemplateTechnicalField {
        self.technical_field
    }

    /// Produces one validated declarative definition without executable content.
    pub fn instantiate(
        self,
        technical_name: Option<&str>,
    ) -> Result<UsageProfileDefinition, DeviceStateValidationError> {
        let placement = match self.id {
            BundledUsageProfileTemplateId::HttpBearerAuthorization => {
                if technical_name.is_some() {
                    return Err(DeviceStateValidationError::new(
                        "Bearer template does not accept a technical name",
                    ));
                }
                UsagePlacement::HttpBearerAuthorization {}
            }
            BundledUsageProfileTemplateId::HttpApiKeyHeader => UsagePlacement::HttpHeader {
                header_name: technical_name
                    .unwrap_or(DEFAULT_API_KEY_HEADER_NAME)
                    .to_owned(),
            },
            BundledUsageProfileTemplateId::CliEnvironmentVariable => {
                let variable_name = technical_name.ok_or_else(|| {
                    DeviceStateValidationError::new(
                        "CLI environment template requires a variable name",
                    )
                })?;
                UsagePlacement::ProcessEnvironment {
                    variable_name: variable_name.to_owned(),
                }
            }
        };
        UsageProfileDefinition::new(self.capability, placement)
    }
}

/// Exact provider-neutral Usage Profile templates bundled with the application.
pub const BUNDLED_USAGE_PROFILE_TEMPLATES: [BundledUsageProfileTemplate; 3] = [
    BundledUsageProfileTemplate::new(
        BundledUsageProfileTemplateId::HttpBearerAuthorization,
        Capability::v1(CapabilityName::HttpRequest),
        UsageProfileTemplateTechnicalField::None,
    ),
    BundledUsageProfileTemplate::new(
        BundledUsageProfileTemplateId::HttpApiKeyHeader,
        Capability::v1(CapabilityName::HttpRequest),
        UsageProfileTemplateTechnicalField::HttpHeaderName {
            suggested_value: DEFAULT_API_KEY_HEADER_NAME,
        },
    ),
    BundledUsageProfileTemplate::new(
        BundledUsageProfileTemplateId::CliEnvironmentVariable,
        Capability::v1(CapabilityName::ProcessRun),
        UsageProfileTemplateTechnicalField::EnvironmentVariableName,
    ),
];

/// Returns the immutable offline template catalog.
#[must_use]
pub const fn bundled_usage_profile_templates() -> &'static [BundledUsageProfileTemplate] {
    &BUNDLED_USAGE_PROFILE_TEMPLATES
}

/// Looks up one bundled template without consulting a network or local state.
#[must_use]
pub fn bundled_usage_profile_template(
    id: BundledUsageProfileTemplateId,
) -> Option<&'static BundledUsageProfileTemplate> {
    BUNDLED_USAGE_PROFILE_TEMPLATES
        .iter()
        .find(|template| template.id() == id)
}

/// Returns an exact offline recommendation for a recognized executable basename.
#[must_use]
pub fn recommend_bundled_usage_profile(
    executable_name: Option<&str>,
) -> Option<BundledUsageProfileRecommendation> {
    let executable_name = executable_name?;
    if executable_name.eq_ignore_ascii_case("gh") {
        return Some(BundledUsageProfileRecommendation::new(
            BundledUsageProfileRecommendationId::GitHubCli,
            BundledUsageProfileTemplateId::CliEnvironmentVariable,
            "GH_TOKEN",
        ));
    }
    if executable_name.eq_ignore_ascii_case("glab") {
        return Some(BundledUsageProfileRecommendation::new(
            BundledUsageProfileRecommendationId::GitLabCli,
            BundledUsageProfileTemplateId::CliEnvironmentVariable,
            "GITLAB_TOKEN",
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn bundled_catalog_is_stable_unique_provider_neutral_and_offline() {
        let templates = bundled_usage_profile_templates();
        assert_eq!(templates.len(), 3);
        assert_eq!(
            templates
                .iter()
                .map(|template| template.id().as_str())
                .collect::<Vec<_>>(),
            vec![
                "http-bearer-authorization",
                "http-api-key-header",
                "cli-environment-variable",
            ]
        );
        assert_eq!(
            templates
                .iter()
                .map(|template| template.id())
                .collect::<BTreeSet<_>>()
                .len(),
            templates.len()
        );

        let source = include_str!("usage_profile_template.rs");
        for forbidden in [
            concat!("https", "://"),
            concat!("http", "://"),
            concat!("github", ".com"),
            concat!("gitlab", ".com"),
            concat!("req", "west"),
            concat!("url", "::"),
        ] {
            assert!(
                !source.to_ascii_lowercase().contains(forbidden),
                "bundled template catalog gained network or provider content"
            );
        }
    }

    #[test]
    fn bundled_template_id_parser_is_exact_and_does_not_reflect_input() {
        for template in bundled_usage_profile_templates() {
            assert_eq!(
                template.id().as_str().parse(),
                Ok(template.id()),
                "stable template identity must round-trip"
            );
        }

        let marker = "provider-secret-marker";
        let error = marker
            .parse::<BundledUsageProfileTemplateId>()
            .expect_err("unknown template must fail");
        assert!(!error.to_string().contains(marker));
    }

    #[test]
    fn bearer_and_api_key_templates_emit_typed_http_definitions() {
        let bearer =
            bundled_usage_profile_template(BundledUsageProfileTemplateId::HttpBearerAuthorization)
                .expect("Bearer template");
        assert_eq!(
            bearer.instantiate(None).expect("Bearer definition"),
            UsageProfileDefinition::new(
                Capability::v1(CapabilityName::HttpRequest),
                UsagePlacement::HttpBearerAuthorization {},
            )
            .expect("expected definition")
        );
        assert!(bearer.instantiate(Some("Authorization")).is_err());

        let api_key =
            bundled_usage_profile_template(BundledUsageProfileTemplateId::HttpApiKeyHeader)
                .expect("API-key template");
        assert_eq!(
            api_key.technical_field(),
            UsageProfileTemplateTechnicalField::HttpHeaderName {
                suggested_value: "X-API-Key"
            }
        );
        for (technical_name, expected_name) in [(None, "X-API-Key"), (Some("Api-Key"), "Api-Key")] {
            assert_eq!(
                api_key
                    .instantiate(technical_name)
                    .expect("API-key definition")
                    .placement(),
                &UsagePlacement::HttpHeader {
                    header_name: expected_name.to_owned()
                }
            );
        }
        assert!(api_key.instantiate(Some("Bad Header")).is_err());
    }

    #[test]
    fn cli_environment_template_requires_a_valid_child_variable_name() {
        let template =
            bundled_usage_profile_template(BundledUsageProfileTemplateId::CliEnvironmentVariable)
                .expect("CLI template");
        assert_eq!(
            template.technical_field(),
            UsageProfileTemplateTechnicalField::EnvironmentVariableName
        );
        assert!(template.instantiate(None).is_err());
        assert!(template.instantiate(Some("BAD-NAME")).is_err());

        let definition = template
            .instantiate(Some("GH_TOKEN"))
            .expect("CLI environment definition");
        assert_eq!(
            definition.capability(),
            Capability::v1(CapabilityName::ProcessRun)
        );
        assert_eq!(
            definition.placement(),
            &UsagePlacement::ProcessEnvironment {
                variable_name: "GH_TOKEN".to_owned()
            }
        );
    }

    #[test]
    fn every_bundled_template_stays_inside_the_declarative_schema() {
        let definitions = [
            BUNDLED_USAGE_PROFILE_TEMPLATES[0]
                .instantiate(None)
                .expect("Bearer"),
            BUNDLED_USAGE_PROFILE_TEMPLATES[1]
                .instantiate(None)
                .expect("API key"),
            BUNDLED_USAGE_PROFILE_TEMPLATES[2]
                .instantiate(Some("TOOL_TOKEN"))
                .expect("CLI environment"),
        ];

        for definition in definitions {
            let encoded = definition.to_json().expect("encode template definition");
            for forbidden in [
                "\"script\"",
                "\"shell\"",
                "\"command\"",
                "\"arguments\"",
                "\"secret_value\"",
                "\"raw_secret\"",
                "\"placeholder\"",
                "\"url\"",
            ] {
                assert!(!encoded.contains(forbidden));
            }
            assert_eq!(
                UsageProfileDefinition::from_json(&encoded).expect("decode definition"),
                definition
            );
        }
    }

    #[test]
    fn recommendations_match_only_exact_observed_executable_names() {
        let github = recommend_bundled_usage_profile(Some("gh")).expect("GitHub CLI");
        assert_eq!(github.id(), BundledUsageProfileRecommendationId::GitHubCli);
        assert_eq!(
            github.template_id(),
            BundledUsageProfileTemplateId::CliEnvironmentVariable
        );
        assert_eq!(github.technical_name(), "GH_TOKEN");
        assert_eq!(
            recommend_bundled_usage_profile(Some("GLAB"))
                .expect("GitLab CLI")
                .technical_name(),
            "GITLAB_TOKEN"
        );
        for unrecognized in [
            None,
            Some("github"),
            Some("my-gh"),
            Some("/usr/local/bin/gh"),
            Some("git"),
        ] {
            assert_eq!(recommend_bundled_usage_profile(unrecognized), None);
        }
    }
}
