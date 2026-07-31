#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Local stdio MCP adapter for the authenticated KeptNear Broker.
//!
//! The adapter owns only its device-local Consumer signing seed. It does not
//! parse vault files, receive the device root key, or expose raw credentials.

mod mcp;
mod tools;

#[cfg(target_os = "macos")]
use keptnear_client::{BrokerAuthenticationStatus, ClientIdentityKind, MacOsBrokerClient};
use mcp::{AdapterAuthenticator, AdapterReadiness, McpServer};
#[cfg(target_os = "macos")]
use psw_broker::{BrokerRequest, BrokerResponse};
#[cfg(target_os = "macos")]
use tools::BrokerToolClient;

pub use keptnear_client::{
    BrokerAdapterError, BrokerAuthenticationStatus as LocalBrokerStatus, PairingProfileId,
    PairingProfileIdError, MAX_PAIRING_PROFILE_ID_BYTES,
};
pub use mcp::{
    McpServerError, MAX_MCP_MESSAGE_BYTES, MCP_PROTOCOL_VERSION_2025_06_18,
    MCP_PROTOCOL_VERSION_LATEST,
};

#[cfg(target_os = "macos")]
struct MacOsAdapterAuthenticator {
    client: MacOsBrokerClient,
}

#[cfg(target_os = "macos")]
impl MacOsAdapterAuthenticator {
    const fn new(profile: PairingProfileId) -> Self {
        Self {
            client: MacOsBrokerClient::new(ClientIdentityKind::Mcp, profile),
        }
    }
}

#[cfg(target_os = "macos")]
impl AdapterAuthenticator for MacOsAdapterAuthenticator {
    fn ensure_authenticated(&mut self) -> AdapterReadiness {
        match self.client.authenticate() {
            Ok(BrokerAuthenticationStatus::Authenticated) => AdapterReadiness::Authenticated,
            Ok(BrokerAuthenticationStatus::PairingPending {
                comparison_code, ..
            }) => AdapterReadiness::PairingPending { comparison_code },
            Err(_) => AdapterReadiness::BrokerUnavailable,
        }
    }
}

#[cfg(target_os = "macos")]
impl BrokerToolClient for MacOsAdapterAuthenticator {
    fn execute(&mut self, request: BrokerRequest) -> Result<BrokerResponse, BrokerAdapterError> {
        self.client.execute(request)
    }
}

/// Runs the macOS KeptNear MCP server over standard input and standard output.
///
/// Standard output is reserved exclusively for newline-delimited JSON-RPC.
#[cfg(target_os = "macos")]
pub fn run_stdio() -> Result<(), McpServerError> {
    run_stdio_for_profile(PairingProfileId::default())
}

/// Runs the macOS KeptNear MCP server with one independently paired profile.
///
/// Distinct profile identifiers select distinct device-local signing keys and
/// therefore distinct Broker Consumers. Reusing a profile intentionally shares
/// one Consumer permission set.
#[cfg(target_os = "macos")]
pub fn run_stdio_for_profile(profile: PairingProfileId) -> Result<(), McpServerError> {
    use std::io;

    let mut server = McpServer::new(MacOsAdapterAuthenticator::new(profile));
    let stdin = io::stdin();
    let stdout = io::stdout();
    server.serve(&mut stdin.lock(), &mut stdout.lock())
}
