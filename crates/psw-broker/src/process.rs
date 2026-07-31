use std::fmt::{Display, Formatter};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use crate::dispatcher::{
    BrokerConnectionState, BrokerDispatchError, BrokerDispatchOutcome, BrokerDispatcher,
};
use crate::process_run::BrokerProcessRunCancellation;
use crate::protocol::{
    read_broker_frame, write_broker_frame, BrokerCapabilitySet, BrokerErrorCode, BrokerFrameError,
    BrokerInstanceId,
};
use crate::runtime::BrokerRuntime;
use crate::state_model::ObservedConsumerIdentity;
use crate::vault_session::{
    BrokerVaultLockEvent, BrokerVaultSessionError, BrokerVaultSessionManager,
    DEFAULT_BROKER_AUTO_LOCK_TIMEOUT,
};

/// Reason a transport-independent Broker connection loop ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerConnectionExit {
    /// The peer closed cleanly between frames.
    PeerClosed,
    /// The Broker wrote a final sanitized response and closed the connection.
    ClosedByBroker,
}

/// Sanitized Broker process-loop failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerProcessError {
    /// Reading the local byte stream failed.
    Read,
    /// Encoding a typed dispatcher response failed.
    Dispatch,
    /// Writing or flushing the local byte stream failed.
    Write,
}

impl Display for BrokerProcessError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Read => "Broker connection read failed",
            Self::Dispatch => "Broker request dispatch failed",
            Self::Write => "Broker connection write failed",
        };
        formatter.write_str(label)
    }
}

impl std::error::Error for BrokerProcessError {}

impl From<BrokerDispatchError> for BrokerProcessError {
    fn from(_: BrokerDispatchError) -> Self {
        Self::Dispatch
    }
}

/// Running Broker process core, independent of its local transport listener.
#[derive(Clone, Debug)]
pub struct BrokerProcess {
    dispatcher: BrokerDispatcher,
    vault_sessions: Arc<BrokerVaultSessionManager>,
}

impl BrokerProcess {
    /// Creates a process that advertises every implemented v1 credential capability.
    pub fn new() -> Result<Self, BrokerVaultSessionError> {
        Self::with_supported_capabilities(BrokerCapabilitySet::machine_credential_v1())
    }

    /// Creates a process with a custom non-zero vault idle timeout.
    pub fn with_auto_lock_timeout(
        auto_lock_timeout: Duration,
    ) -> Result<Self, BrokerVaultSessionError> {
        Ok(Self {
            dispatcher: BrokerDispatcher::new(
                BrokerInstanceId::generate(),
                BrokerCapabilitySet::machine_credential_v1(),
            ),
            vault_sessions: Arc::new(BrokerVaultSessionManager::new(auto_lock_timeout)?),
        })
    }

    pub(crate) fn with_supported_capabilities(
        supported_capabilities: BrokerCapabilitySet,
    ) -> Result<Self, BrokerVaultSessionError> {
        Ok(Self {
            dispatcher: BrokerDispatcher::new(BrokerInstanceId::generate(), supported_capabilities),
            vault_sessions: Arc::new(BrokerVaultSessionManager::new(
                DEFAULT_BROKER_AUTO_LOCK_TIMEOUT,
            )?),
        })
    }

    /// Returns the process instance identity used by non-secret status responses.
    #[must_use]
    pub const fn broker_instance_id(&self) -> BrokerInstanceId {
        self.dispatcher.broker_instance_id()
    }

    /// Returns the versioned request dispatcher.
    #[must_use]
    pub const fn dispatcher(&self) -> &BrokerDispatcher {
        &self.dispatcher
    }

    /// Returns the process-shared machine-facing vault-session manager.
    #[must_use]
    pub fn vault_sessions(&self) -> &BrokerVaultSessionManager {
        &self.vault_sessions
    }

    /// Locks and discards all process-owned vault sessions before teardown.
    pub fn shutdown_vault_sessions(
        &self,
    ) -> Result<Vec<BrokerVaultLockEvent>, BrokerVaultSessionError> {
        self.vault_sessions.shutdown()
    }

    /// Serves one already-established local connection until either side closes.
    ///
    /// This method does not open a socket or network listener. The
    /// permission-restricted Unix transport is a separate boundary.
    pub fn serve_connection(
        &self,
        reader: &mut impl Read,
        writer: &mut impl Write,
    ) -> Result<BrokerConnectionExit, BrokerProcessError> {
        self.serve_connection_with_dispatch(reader, writer, |state, payload| {
            self.dispatcher.dispatch(state, payload)
        })
    }

    pub(crate) fn serve_runtime_connection_with_process_cancellation(
        &self,
        runtime: &BrokerRuntime,
        observed_identity: &ObservedConsumerIdentity,
        reader: &mut impl Read,
        writer: &mut impl Write,
        process_cancellation: &BrokerProcessRunCancellation,
    ) -> Result<BrokerConnectionExit, BrokerProcessError> {
        self.serve_connection_with_dispatch(reader, writer, |state, payload| {
            self.dispatcher.dispatch_runtime_with_process_cancellation(
                runtime,
                observed_identity,
                state,
                payload,
                process_cancellation,
            )
        })
    }

    fn serve_connection_with_dispatch(
        &self,
        reader: &mut impl Read,
        writer: &mut impl Write,
        mut dispatch: impl FnMut(
            &mut BrokerConnectionState,
            &[u8],
        ) -> Result<BrokerDispatchOutcome, BrokerDispatchError>,
    ) -> Result<BrokerConnectionExit, BrokerProcessError> {
        let mut state = BrokerConnectionState::awaiting_hello();
        loop {
            let payload = match read_broker_frame(reader) {
                Ok(Some(payload)) => payload,
                Ok(None) => return Ok(BrokerConnectionExit::PeerClosed),
                Err(BrokerFrameError::Read) => return Err(BrokerProcessError::Read),
                Err(BrokerFrameError::Write) => return Err(BrokerProcessError::Read),
                Err(BrokerFrameError::Oversized) => {
                    let outcome = self
                        .dispatcher
                        .transport_error_outcome(BrokerErrorCode::OversizedFrame)?;
                    self.write_outcome(writer, &outcome)?;
                    return Ok(BrokerConnectionExit::ClosedByBroker);
                }
                Err(BrokerFrameError::Empty | BrokerFrameError::Truncated) => {
                    let outcome = self
                        .dispatcher
                        .transport_error_outcome(BrokerErrorCode::MalformedFrame)?;
                    self.write_outcome(writer, &outcome)?;
                    return Ok(BrokerConnectionExit::ClosedByBroker);
                }
            };

            let outcome = dispatch(&mut state, &payload)?;
            self.write_outcome(writer, &outcome)?;
            if outcome.should_close_connection() {
                return Ok(BrokerConnectionExit::ClosedByBroker);
            }
        }
    }

    fn write_outcome(
        &self,
        writer: &mut impl Write,
        outcome: &BrokerDispatchOutcome,
    ) -> Result<(), BrokerProcessError> {
        write_broker_frame(writer, outcome.response_payload())
            .map_err(|_| BrokerProcessError::Write)?;
        writer.flush().map_err(|_| BrokerProcessError::Write)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};

    use crate::protocol::{
        decode_broker_response, encode_broker_request, read_broker_frame, write_broker_frame,
        BrokerHelloRequest, BrokerProtocolVersion, BrokerProtocolVersionRange, BrokerRequest,
        BrokerRequestEnvelope, BrokerRequestId, BrokerResponse, MAX_BROKER_FRAME_LENGTH,
    };

    use super::*;

    fn request_frame(request: BrokerRequestEnvelope) -> Vec<u8> {
        let payload = encode_broker_request(&request).expect("request");
        let mut frame = Vec::new();
        write_broker_frame(&mut frame, &payload).expect("frame");
        frame
    }

    fn hello_request() -> BrokerRequestEnvelope {
        BrokerRequestEnvelope::new(
            BrokerProtocolVersion::current(),
            BrokerRequestId::generate(),
            BrokerRequest::Hello(
                BrokerHelloRequest::new(
                    vec![BrokerProtocolVersionRange::new(1, 0, 0).expect("range")],
                    vec![],
                )
                .expect("hello"),
            ),
        )
    }

    #[test]
    fn process_serves_hello_and_status_on_one_connection() {
        let process = BrokerProcess::new().expect("process");
        let hello = hello_request();
        let status = BrokerRequestEnvelope::new(
            BrokerProtocolVersion::current(),
            BrokerRequestId::generate(),
            BrokerRequest::Status,
        );
        let mut input = request_frame(hello.clone());
        input.extend(request_frame(status.clone()));
        let mut output = Vec::new();

        assert_eq!(
            process
                .serve_connection(&mut Cursor::new(input), &mut output)
                .expect("serve"),
            BrokerConnectionExit::PeerClosed
        );

        let mut output = Cursor::new(output);
        let hello_response = decode_broker_response(
            &read_broker_frame(&mut output)
                .expect("frame")
                .expect("hello response"),
        )
        .expect("response");
        assert_eq!(hello_response.request_id(), hello.request_id());
        assert!(matches!(
            hello_response.response(),
            BrokerResponse::Hello(_)
        ));

        let status_response = decode_broker_response(
            &read_broker_frame(&mut output)
                .expect("frame")
                .expect("status response"),
        )
        .expect("response");
        assert_eq!(status_response.request_id(), status.request_id());
        assert_eq!(
            status_response.response(),
            &BrokerResponse::Status(crate::protocol::BrokerStatusResponse::new(
                process.broker_instance_id()
            ))
        );
        assert_eq!(read_broker_frame(&mut output).expect("EOF"), None);
    }

    #[test]
    fn process_rejects_oversized_length_before_reading_payload() {
        struct HeaderOnlyReader {
            header: Cursor<[u8; 4]>,
            reads: usize,
        }

        impl Read for HeaderOnlyReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                self.reads += 1;
                self.header.read(buffer)
            }
        }

        let mut reader = HeaderOnlyReader {
            header: Cursor::new(((MAX_BROKER_FRAME_LENGTH + 1) as u32).to_be_bytes()),
            reads: 0,
        };
        let mut output = Vec::new();
        assert_eq!(
            BrokerProcess::new()
                .expect("process")
                .serve_connection(&mut reader, &mut output)
                .expect("serve"),
            BrokerConnectionExit::ClosedByBroker
        );
        assert_eq!(reader.reads, 1);
        let response = decode_broker_response(
            &read_broker_frame(&mut Cursor::new(output))
                .expect("frame")
                .expect("response"),
        )
        .expect("response");
        assert!(matches!(
            response.response(),
            BrokerResponse::Error(error)
                if error.error_code() == BrokerErrorCode::OversizedFrame
        ));
    }

    #[test]
    fn process_closes_after_malformed_frame_without_reflecting_input() {
        let secret_marker = b"KN_PROCESS_SECRET_MARKER";
        let mut input = Vec::new();
        write_broker_frame(&mut input, secret_marker).expect("frame");
        let mut output = Vec::new();
        assert_eq!(
            BrokerProcess::new()
                .expect("process")
                .serve_connection(&mut Cursor::new(input), &mut output)
                .expect("serve"),
            BrokerConnectionExit::ClosedByBroker
        );
        assert!(!output
            .windows(secret_marker.len())
            .any(|window| window == secret_marker));
    }

    #[test]
    fn process_reports_sanitized_write_failure() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "sensitive detail",
                ))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut input = Cursor::new(request_frame(hello_request()));
        assert_eq!(
            BrokerProcess::new()
                .expect("process")
                .serve_connection(&mut input, &mut FailingWriter),
            Err(BrokerProcessError::Write)
        );
        assert_eq!(
            BrokerProcessError::Write.to_string(),
            "Broker connection write failed"
        );
    }

    #[test]
    fn process_identity_is_random_per_instance_and_stable_within_one_instance() {
        let first = BrokerProcess::new().expect("first process");
        let second = BrokerProcess::new().expect("second process");
        assert_ne!(first.broker_instance_id(), second.broker_instance_id());
        assert_eq!(
            first.broker_instance_id(),
            first.dispatcher().broker_instance_id()
        );
    }

    #[test]
    fn process_clones_share_one_shutdown_aware_vault_session_manager() {
        let process = BrokerProcess::new().expect("process");
        let peer_process = process.clone();
        assert!(!process.vault_sessions().is_shutdown().expect("state"));
        assert!(peer_process
            .shutdown_vault_sessions()
            .expect("shutdown")
            .is_empty());
        assert!(process.vault_sessions().is_shutdown().expect("state"));
        assert!(process
            .shutdown_vault_sessions()
            .expect("repeat shutdown")
            .is_empty());
    }
}
