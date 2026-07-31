use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::{BROKER_PROTOCOL_MAJOR, BROKER_PROTOCOL_MINOR, BROKER_PROTOCOL_NAME};

/// Stable schema identifier emitted by packaged KeptNear components.
pub const COMPONENT_METADATA_SCHEMA: &str = "keptnear.component-metadata.v1";

const MAX_COMPONENT_VERSION_BYTES: usize = 128;

/// One component that participates in the local KeptNear product package.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackagedComponent {
    /// Interactive macOS application.
    #[serde(rename = "macos-app")]
    MacOsApp,
    /// Local credential Broker service.
    Broker,
    /// Local stdio MCP adapter.
    McpAdapter,
    /// Public local command-line adapter.
    Cli,
}

/// Exact Broker protocol declaration shared by local components.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentBrokerProtocol {
    name: String,
    major: u16,
    minor: u16,
}

impl ComponentBrokerProtocol {
    /// Returns the stable protocol name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the protocol major version.
    #[must_use]
    pub const fn major(&self) -> u16 {
        self.major
    }

    /// Returns the protocol minor version.
    #[must_use]
    pub const fn minor(&self) -> u16 {
        self.minor
    }
}

/// Secret-free compatibility metadata printed without contacting the Broker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentMetadata {
    schema: String,
    component: PackagedComponent,
    component_version: String,
    broker_protocol: ComponentBrokerProtocol,
}

impl ComponentMetadata {
    /// Builds metadata for one component compiled against the current protocol.
    pub fn current(
        component: PackagedComponent,
        component_version: &str,
    ) -> Result<Self, ComponentMetadataError> {
        validate_component_version(component_version)?;
        Ok(Self {
            schema: COMPONENT_METADATA_SCHEMA.to_owned(),
            component,
            component_version: component_version.to_owned(),
            broker_protocol: ComponentBrokerProtocol {
                name: BROKER_PROTOCOL_NAME.to_owned(),
                major: BROKER_PROTOCOL_MAJOR,
                minor: BROKER_PROTOCOL_MINOR,
            },
        })
    }

    /// Returns the stable metadata schema identifier.
    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns the represented package component.
    #[must_use]
    pub const fn component(&self) -> PackagedComponent {
        self.component
    }

    /// Returns the component's package version.
    #[must_use]
    pub fn component_version(&self) -> &str {
        &self.component_version
    }

    /// Returns the exact Broker protocol declaration.
    #[must_use]
    pub const fn broker_protocol(&self) -> &ComponentBrokerProtocol {
        &self.broker_protocol
    }
}

/// A package version cannot be represented safely in component metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentMetadataError;

impl Display for ComponentMetadataError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("component version is invalid")
    }
}

impl std::error::Error for ComponentMetadataError {}

fn validate_component_version(value: &str) -> Result<(), ComponentMetadataError> {
    if value.is_empty()
        || value.len() > MAX_COMPONENT_VERSION_BYTES
        || !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
    {
        return Err(ComponentMetadataError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn current_metadata_is_closed_secret_free_and_protocol_exact() {
        let metadata = ComponentMetadata::current(PackagedComponent::McpAdapter, "0.1.0-alpha.1")
            .expect("metadata");
        let value = serde_json::to_value(&metadata).expect("serialize");

        assert_eq!(
            value,
            json!({
                "schema": "keptnear.component-metadata.v1",
                "component": "mcp-adapter",
                "component_version": "0.1.0-alpha.1",
                "broker_protocol": {
                    "name": "keptnear.broker",
                    "major": 1,
                    "minor": 0
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<ComponentMetadata>(value).expect("decode"),
            metadata
        );
    }

    #[test]
    fn component_versions_reject_empty_unbounded_non_ascii_and_json_material() {
        for version in [
            "",
            "0.1.0 alpha",
            "0.1.0\"",
            "版本",
            &"a".repeat(MAX_COMPONENT_VERSION_BYTES + 1),
        ] {
            assert_eq!(
                ComponentMetadata::current(PackagedComponent::Broker, version),
                Err(ComponentMetadataError)
            );
        }
    }
}
