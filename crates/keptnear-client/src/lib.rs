#![deny(missing_docs)]
#![deny(unsafe_code)]

//! Shared first-party client for the authenticated local KeptNear Broker.
//!
//! The client owns only one device-local Consumer signing seed. It negotiates
//! and authenticates over local IPC, never parses a vault, and never receives
//! the Broker device root or a vault root key.

mod broker_client;
mod human_control_client;
mod identity;
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos_keychain;

pub use broker_client::{BrokerAdapterError, BrokerAuthenticationStatus};
pub use human_control_client::{HumanControlClient, HumanControlClientError, HumanControlSigner};
pub use identity::{
    ClientIdentityKind, PairingProfileId, PairingProfileIdError, MAX_PAIRING_PROFILE_ID_BYTES,
};

#[cfg(target_os = "macos")]
use broker_client::BrokerClient;
#[cfg(target_os = "macos")]
use identity::{load_or_create_identity, ConsumerIdentity};
#[cfg(target_os = "macos")]
use macos_keychain::MacOsConsumerIdentityStore;
#[cfg(target_os = "macos")]
use psw_broker::{
    BrokerRequest, BrokerResponse, BrokerStatusResponse, ControllerKeyStore,
    ControllerKeychainAccessGroup, DevicePaths, HumanControlRequest, HumanControlSuccessEnvelope,
    MacOsControllerKeyStore, UnixBrokerConnection,
};
#[cfg(target_os = "macos")]
use std::time::Duration;

/// Authenticated first-party Broker client using the owner-only macOS socket.
///
/// The selected client kind and profile choose one non-synchronizing,
/// device-only Keychain signing seed. Neither selector is sent as a Broker
/// authorization identity.
#[cfg(target_os = "macos")]
pub struct MacOsBrokerClient {
    identity_store: MacOsConsumerIdentityStore,
    identity: Option<ConsumerIdentity>,
    client: Option<BrokerClient<UnixBrokerConnection>>,
}

/// Authenticated Human Control client for an activation-qualified macOS App.
#[cfg(target_os = "macos")]
pub struct MacOsHumanControlClient {
    key_store: MacOsControllerKeyStore,
    client: Option<HumanControlClient<UnixBrokerConnection>>,
    operation_timeout: Duration,
}

#[cfg(target_os = "macos")]
impl MacOsHumanControlClient {
    /// Creates a lazy client for one verified shared Keychain access group.
    #[must_use]
    pub const fn new(
        access_group: ControllerKeychainAccessGroup,
        operation_timeout: Duration,
    ) -> Self {
        Self {
            key_store: MacOsControllerKeyStore::new(access_group),
            client: None,
            operation_timeout,
        }
    }

    /// Loads only an existing controller key and authenticates the connection.
    pub fn authenticate(&mut self) -> Result<(), HumanControlClientError> {
        let signing_key = self
            .key_store
            .load_seed()
            .map_err(|_| HumanControlClientError::ControllerUnavailable)?
            .ok_or(HumanControlClientError::ControllerUnavailable)?;
        self.connect()?;
        let result = self
            .client
            .as_mut()
            .ok_or(HumanControlClientError::Transport)?
            .authenticate(&signing_key);
        self.reset_after_connection_failure(&result);
        result
    }

    /// Executes one already-authenticated Human Control request.
    pub fn execute(
        &mut self,
        request: HumanControlRequest,
    ) -> Result<HumanControlSuccessEnvelope, HumanControlClientError> {
        let result = self
            .client
            .as_mut()
            .ok_or(HumanControlClientError::Transport)?
            .execute(request);
        self.reset_after_connection_failure(&result);
        result
    }

    fn connect(&mut self) -> Result<(), HumanControlClientError> {
        if self.operation_timeout.is_zero() {
            return Err(HumanControlClientError::Transport);
        }
        if self.client.is_none() {
            let paths = DevicePaths::prepare_for_current_user()
                .map_err(|_| HumanControlClientError::Transport)?;
            let connection =
                UnixBrokerConnection::connect_with_timeout(&paths, self.operation_timeout)
                    .map_err(|_| HumanControlClientError::Transport)?;
            connection
                .set_operation_timeout(Some(self.operation_timeout))
                .map_err(|_| HumanControlClientError::Transport)?;
            self.client = Some(HumanControlClient::new(connection));
        }
        Ok(())
    }

    fn reset_after_connection_failure<T>(&mut self, result: &Result<T, HumanControlClientError>) {
        if matches!(
            result,
            Err(HumanControlClientError::Transport | HumanControlClientError::Protocol)
                | Err(HumanControlClientError::Broker {
                    code: psw_broker::HumanControlFailureCode::ProtocolIncompatible
                        | psw_broker::HumanControlFailureCode::AuthenticationRequired
                        | psw_broker::HumanControlFailureCode::RepairRequired,
                    ..
                })
        ) {
            self.client = None;
        }
    }
}

#[cfg(target_os = "macos")]
impl MacOsBrokerClient {
    /// Creates a lazy local client without touching the Keychain or socket.
    #[must_use]
    pub const fn new(client_kind: ClientIdentityKind, profile: PairingProfileId) -> Self {
        Self {
            identity_store: MacOsConsumerIdentityStore::new(client_kind, profile),
            identity: None,
            client: None,
        }
    }

    /// Reads non-secret Broker process status without creating a Consumer key.
    pub fn status(&mut self) -> Result<BrokerStatusResponse, BrokerAdapterError> {
        self.connect()?;
        let result = self
            .client
            .as_mut()
            .ok_or(BrokerAdapterError::Transport)?
            .status();
        self.reset_after_transport_failure(&result);
        result
    }

    /// Ensures this profile is paired and proves possession for this connection.
    pub fn authenticate(&mut self) -> Result<BrokerAuthenticationStatus, BrokerAdapterError> {
        self.prepare_identity()?;
        self.connect()?;
        let result = self
            .client
            .as_mut()
            .ok_or(BrokerAdapterError::Transport)?
            .authenticate(self.identity.as_ref().ok_or(BrokerAdapterError::Identity)?);
        self.reset_after_transport_failure(&result);
        result
    }

    /// Executes one capability request after successful connection authentication.
    pub fn execute(
        &mut self,
        request: BrokerRequest,
    ) -> Result<BrokerResponse, BrokerAdapterError> {
        let result = self
            .client
            .as_mut()
            .ok_or(BrokerAdapterError::Transport)?
            .execute(request);
        self.reset_after_transport_failure(&result);
        result
    }

    fn prepare_identity(&mut self) -> Result<(), BrokerAdapterError> {
        if self.identity.is_none() {
            self.identity = Some(
                load_or_create_identity(&self.identity_store)
                    .map_err(|_| BrokerAdapterError::Identity)?,
            );
        }
        Ok(())
    }

    fn connect(&mut self) -> Result<(), BrokerAdapterError> {
        if self.client.is_none() {
            let paths = DevicePaths::prepare_for_current_user()
                .map_err(|_| BrokerAdapterError::Transport)?;
            let connection =
                UnixBrokerConnection::connect(&paths).map_err(|_| BrokerAdapterError::Transport)?;
            self.client = Some(BrokerClient::new(connection));
        }
        Ok(())
    }

    fn reset_after_transport_failure<T>(&mut self, result: &Result<T, BrokerAdapterError>) {
        if matches!(result, Err(BrokerAdapterError::Transport)) {
            self.client = None;
        }
    }
}
