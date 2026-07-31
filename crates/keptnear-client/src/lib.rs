#![deny(missing_docs)]
#![deny(unsafe_code)]

//! Shared first-party client for the authenticated local KeptNear Broker.
//!
//! The client owns only one device-local Consumer signing seed. It negotiates
//! and authenticates over local IPC, never parses a vault, and never receives
//! the Broker device root or a vault root key.

mod broker_client;
mod identity;
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos_keychain;

pub use broker_client::{BrokerAdapterError, BrokerAuthenticationStatus};
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
    BrokerRequest, BrokerResponse, BrokerStatusResponse, DevicePaths, UnixBrokerConnection,
};

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
