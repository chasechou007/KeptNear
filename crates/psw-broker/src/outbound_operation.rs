use std::fmt::{Debug, Display, Formatter};

use crate::state_model::{
    AuditDecision, AuditEvent, AuditEventId, AuditEventKind, AuditScope, AuthorizationTarget,
    CapabilityName, ConfirmationMethod, ConsumerId, CredentialFieldScope, StateTimestamp,
    UseGrantId,
};
use crate::state_store::{DeviceStateError, DeviceStateStore};
use crate::use_grant::BrokerAuthorizedGrantUse;

/// Final non-secret outcome of one explicit credential-bearing operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerOutboundOperationOutcome {
    /// The explicitly requested HTTP or child-process operation completed.
    Succeeded,
    /// The explicitly requested operation started but did not complete successfully.
    Failed,
}

impl BrokerOutboundOperationOutcome {
    const fn audit_decision(self) -> AuditDecision {
        match self {
            Self::Succeeded => AuditDecision::Allowed,
            Self::Failed => AuditDecision::Failed,
        }
    }
}

/// Opaque proof that one explicit outbound operation passed Use Grant checks.
///
/// The value contains only stable attribution and can be finalized once. It
/// carries no destination, request, command, response, or secret material.
#[must_use = "an authorized outbound operation must be finalized with its non-secret outcome"]
#[derive(Eq, PartialEq)]
pub struct BrokerOutboundOperationAuthorization {
    authorization_event_id: AuditEventId,
    scope: AuditScope,
    confirmation_method: ConfirmationMethod,
}

impl BrokerOutboundOperationAuthorization {
    /// Returns the pending audit event created before the operation may start.
    #[must_use]
    pub const fn authorization_event_id(&self) -> AuditEventId {
        self.authorization_event_id
    }

    /// Returns the paired Consumer attributable to this operation.
    #[must_use]
    pub fn consumer_id(&self) -> ConsumerId {
        self.scope
            .consumer_id()
            .expect("outbound operation always has a Consumer")
    }

    /// Returns the exact authorized credential field.
    #[must_use]
    pub fn field_scope(&self) -> CredentialFieldScope {
        self.scope
            .field_scope()
            .expect("outbound operation always has a field")
    }

    /// Returns the exact versioned outbound capability.
    #[must_use]
    pub fn capability(&self) -> crate::state_model::Capability {
        self.scope
            .capability()
            .expect("outbound operation always has a capability")
    }

    /// Returns the Use Grant that authorized this operation.
    #[must_use]
    pub fn use_grant_id(&self) -> UseGrantId {
        self.scope
            .use_grant_id()
            .expect("outbound operation always has a Use Grant")
    }
}

impl Debug for BrokerOutboundOperationAuthorization {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerOutboundOperationAuthorization")
            .field("authorization_event_id", &self.authorization_event_id)
            .field("capability", &self.capability())
            .finish_non_exhaustive()
    }
}

/// Sanitized failure while attributing an explicit outbound operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerOutboundOperationError {
    /// The requested capability is not an outbound credential-use capability.
    UnsupportedCapability,
    /// Authenticated encrypted audit state could not be written.
    DeviceState(DeviceStateError),
}

impl Display for BrokerOutboundOperationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedCapability => {
                formatter.write_str("outbound operation capability is unsupported")
            }
            Self::DeviceState(source) => {
                write!(formatter, "outbound operation audit failed: {source}")
            }
        }
    }
}

impl std::error::Error for BrokerOutboundOperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DeviceState(source) => Some(source),
            Self::UnsupportedCapability => None,
        }
    }
}

impl From<DeviceStateError> for BrokerOutboundOperationError {
    fn from(source: DeviceStateError) -> Self {
        Self::DeviceState(source)
    }
}

pub(crate) struct BrokerOutboundOperationManager;

impl BrokerOutboundOperationManager {
    pub(crate) fn validate_target(
        target: AuthorizationTarget,
    ) -> Result<(), BrokerOutboundOperationError> {
        if !matches!(
            target.capability().name(),
            CapabilityName::HttpRequest | CapabilityName::ProcessRun
        ) {
            return Err(BrokerOutboundOperationError::UnsupportedCapability);
        }
        Ok(())
    }

    pub(crate) fn begin(
        state: &DeviceStateStore,
        authorized: BrokerAuthorizedGrantUse,
        started_at: StateTimestamp,
    ) -> Result<BrokerOutboundOperationAuthorization, BrokerOutboundOperationError> {
        let grant = authorized.grant();
        let target = grant.target();
        Self::validate_target(target)?;
        let scope = AuditScope::new(
            Some(target.consumer_id()),
            Some(target.field_scope()),
            Some(target.capability()),
            Some(grant.use_grant_id()),
        );
        let confirmation_method = if grant.source_rule_id().is_some() {
            ConfirmationMethod::PersistentRule
        } else {
            ConfirmationMethod::UserApproval
        };
        let event = AuditEvent::new(
            started_at,
            AuditEventKind::CredentialUse,
            scope,
            AuditDecision::Pending,
            confirmation_method,
        );
        let authorization_event_id = event.audit_event_id();
        state.append_audit_event(&event)?;
        Ok(BrokerOutboundOperationAuthorization {
            authorization_event_id,
            scope,
            confirmation_method,
        })
    }

    pub(crate) fn finish(
        state: &DeviceStateStore,
        authorization: BrokerOutboundOperationAuthorization,
        outcome: BrokerOutboundOperationOutcome,
        completed_at: StateTimestamp,
    ) -> Result<AuditEventId, BrokerOutboundOperationError> {
        let event = AuditEvent::new(
            completed_at,
            AuditEventKind::CredentialUse,
            authorization.scope,
            outcome.audit_decision(),
            authorization.confirmation_method,
        );
        let audit_event_id = event.audit_event_id();
        state.append_audit_event(&event)?;
        Ok(audit_event_id)
    }

    pub(crate) fn record_denied(
        state: &DeviceStateStore,
        target: AuthorizationTarget,
        use_grant_id: UseGrantId,
        decision: AuditDecision,
        occurred_at: StateTimestamp,
    ) -> Result<AuditEventId, BrokerOutboundOperationError> {
        Self::validate_target(target)?;
        debug_assert!(matches!(
            decision,
            AuditDecision::Denied | AuditDecision::Paused
        ));
        let event = AuditEvent::new(
            occurred_at,
            AuditEventKind::CredentialUse,
            AuditScope::new(
                Some(target.consumer_id()),
                Some(target.field_scope()),
                Some(target.capability()),
                Some(use_grant_id),
            ),
            decision,
            ConfirmationMethod::None,
        );
        let audit_event_id = event.audit_event_id();
        state.append_audit_event(&event)?;
        Ok(audit_event_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_has_only_fixed_non_secret_audit_decisions() {
        assert_eq!(
            BrokerOutboundOperationOutcome::Succeeded.audit_decision(),
            AuditDecision::Allowed
        );
        assert_eq!(
            BrokerOutboundOperationOutcome::Failed.audit_decision(),
            AuditDecision::Failed
        );
    }

    #[test]
    fn attribution_model_has_no_payload_or_background_network_fields() {
        let source = include_str!("outbound_operation.rs");
        for forbidden in [
            concat!("secret_", "value:"),
            concat!("credential_", "title:"),
            concat!("request_", "url:"),
            concat!("request_", "body:"),
            concat!("command_", "arguments:"),
            concat!("standard_", "output:"),
            concat!("standard_", "error:"),
            concat!("response_", "body:"),
            concat!("vault_", "path:"),
            concat!("executable_", "path:"),
            concat!("telemetry_", "endpoint:"),
            concat!("template_", "url:"),
            concat!("background_", "network:"),
        ] {
            assert!(
                !source.contains(forbidden),
                "outbound attribution added forbidden field {forbidden}"
            );
        }
        assert!(!source.contains(concat!("std::", "net")));
    }
}
