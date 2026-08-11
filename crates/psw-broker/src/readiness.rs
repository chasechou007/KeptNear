use std::fmt::{Display, Formatter};

use crate::{
    BrokerVaultSessionError, BrokerVaultSessionSnapshot, ComponentMetadata,
    HumanControlProtocolVersion, PackagedComponent,
};

/// Fixed protected-state category exposed after authenticated runtime startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerProtectedStateCategory {
    /// SQLCipher state was authenticated and its current schema verified.
    Authenticated,
}

/// Path-free readiness projection for an authenticated human controller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerReadinessProjection {
    component: ComponentMetadata,
    human_control_protocol: HumanControlProtocolVersion,
    protected_state: BrokerProtectedStateCategory,
    machine_access_paused: bool,
    vaults: Vec<BrokerVaultSessionSnapshot>,
}

impl BrokerReadinessProjection {
    pub(crate) fn new(
        machine_access_paused: bool,
        mut vaults: Vec<BrokerVaultSessionSnapshot>,
    ) -> Self {
        vaults.sort_by_key(|snapshot| snapshot.vault_id());
        Self {
            component: ComponentMetadata::current(
                PackagedComponent::Broker,
                env!("CARGO_PKG_VERSION"),
            )
            .expect("Cargo package version is valid component metadata"),
            human_control_protocol: HumanControlProtocolVersion::current(),
            protected_state: BrokerProtectedStateCategory::Authenticated,
            machine_access_paused,
            vaults,
        }
    }

    /// Returns the exact packaged Broker identity and Consumer protocol version.
    #[must_use]
    pub const fn component(&self) -> &ComponentMetadata {
        &self.component
    }

    /// Returns the authenticated App-to-Broker protocol version.
    #[must_use]
    pub const fn human_control_protocol(&self) -> HumanControlProtocolVersion {
        self.human_control_protocol
    }

    /// Returns the fixed protected-state category without a path or SQL detail.
    #[must_use]
    pub const fn protected_state(&self) -> BrokerProtectedStateCategory {
        self.protected_state
    }

    /// Returns the independent persisted Machine Access Pause state.
    #[must_use]
    pub const fn machine_access_paused(&self) -> bool {
        self.machine_access_paused
    }

    /// Returns stable identities and lock states for tracked machine Vaults.
    #[must_use]
    pub fn vaults(&self) -> &[BrokerVaultSessionSnapshot] {
        &self.vaults
    }
}

/// Fixed readiness projection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerReadinessError {
    /// Process-owned Vault lock state could not be read safely.
    VaultStateUnavailable,
}

impl Display for BrokerReadinessError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Broker readiness is unavailable")
    }
}

impl std::error::Error for BrokerReadinessError {}

impl From<BrokerVaultSessionError> for BrokerReadinessError {
    fn from(_: BrokerVaultSessionError) -> Self {
        Self::VaultStateUnavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_readiness_is_component_exact_pause_independent_and_path_free() {
        let projection = BrokerReadinessProjection::new(true, Vec::new());
        assert_eq!(
            projection.component().component(),
            PackagedComponent::Broker
        );
        assert_eq!(
            projection.human_control_protocol(),
            HumanControlProtocolVersion::current()
        );
        assert_eq!(
            projection.protected_state(),
            BrokerProtectedStateCategory::Authenticated
        );
        assert!(projection.machine_access_paused());
        assert!(projection.vaults().is_empty());
        let debug = format!("{projection:?}");
        for forbidden in ["/Users/", "/private/", ".pswvault", "device-v1.db"] {
            assert!(!debug.contains(forbidden));
        }
    }
}
