use std::fmt::{Display, Formatter};
use std::io::{Read, Write};

use psw_broker::{
    broker_authentication_transcript, consumer_pairing_transcript, decode_broker_response,
    encode_broker_request, read_broker_frame, write_broker_frame,
    BrokerAuthenticationCompleteRequest, BrokerAuthenticationStartRequest, BrokerErrorCode,
    BrokerHelloRequest, BrokerPairingCompleteRequest, BrokerPairingProgressResponse,
    BrokerPairingRequestStatus, BrokerPairingStartRequest, BrokerProtocolVersion,
    BrokerProtocolVersionRange, BrokerRequest, BrokerRequestEnvelope, BrokerRequestId,
    BrokerRequiredAction, BrokerResponse, BrokerSessionId, CapabilityName, ConsumerId,
    PairingComparisonCode, PairingRequestId, PAIRING_NONCE_LENGTH,
};
use rand_core::{OsRng, RngCore};

use crate::identity::ConsumerIdentity;

/// Non-secret state of the adapter's Broker authentication attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerAuthenticationStatus {
    /// This process holds an authenticated Consumer session.
    Authenticated,
    /// Pairing exists but still requires local human approval.
    PairingPending {
        /// Random request identity shown only for local troubleshooting.
        pairing_request_id: PairingRequestId,
        /// Human comparison code shown by the adapter and KeptNear App.
        comparison_code: PairingComparisonCode,
    },
}

/// Sanitized local Broker client failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerAdapterError {
    /// The device-only Consumer identity could not be loaded or created.
    Identity,
    /// Local framing or stream I/O failed.
    Transport,
    /// A response violated the negotiated typed protocol.
    Protocol,
    /// The Broker returned one stable non-secret error.
    Broker {
        /// Stable Broker error category.
        error_code: BrokerErrorCode,
        /// Whether a bounded retry may succeed.
        retryable: bool,
        /// Optional stable next action.
        required_action: Option<BrokerRequiredAction>,
        /// Optional asynchronous approval identity.
        approval_request_id: Option<psw_broker::ApprovalRequestId>,
    },
}

impl Display for BrokerAdapterError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Identity => "local Consumer identity is unavailable",
            Self::Transport => "local Broker transport failed",
            Self::Protocol => "local Broker protocol failed",
            Self::Broker { .. } => "local Broker rejected the adapter request",
        };
        formatter.write_str(label)
    }
}

impl std::error::Error for BrokerAdapterError {}

pub(crate) struct BrokerClient<Stream> {
    stream: Stream,
    negotiated: bool,
    authenticated_session: Option<(BrokerSessionId, ConsumerId)>,
}

impl<Stream> BrokerClient<Stream>
where
    Stream: Read + Write,
{
    pub(crate) const fn new(stream: Stream) -> Self {
        Self {
            stream,
            negotiated: false,
            authenticated_session: None,
        }
    }

    pub(crate) fn authenticate(
        &mut self,
        identity: &ConsumerIdentity,
    ) -> Result<BrokerAuthenticationStatus, BrokerAdapterError> {
        if self.authenticated_session.is_some() {
            return Ok(BrokerAuthenticationStatus::Authenticated);
        }
        self.negotiate()?;

        let public_key = identity.public_key();
        let mut client_nonce = [0_u8; PAIRING_NONCE_LENGTH];
        OsRng.fill_bytes(&mut client_nonce);
        let progress = self.request(BrokerRequest::PairingStart(
            BrokerPairingStartRequest::new(public_key, client_nonce),
        ))?;
        let consumer_id = match progress {
            BrokerResponse::PairingProgress(BrokerPairingProgressResponse::Active {
                consumer_id,
            }) => consumer_id,
            BrokerResponse::PairingProgress(BrokerPairingProgressResponse::Pending(pending)) => {
                match pending.status() {
                    BrokerPairingRequestStatus::AwaitingUserApproval => {
                        return Ok(BrokerAuthenticationStatus::PairingPending {
                            pairing_request_id: pending.pairing_request_id(),
                            comparison_code: pending.comparison_code(),
                        });
                    }
                    BrokerPairingRequestStatus::AwaitingProof => {
                        let consumer_id =
                            pending.consumer_id().ok_or(BrokerAdapterError::Protocol)?;
                        let proof = identity.sign(&consumer_pairing_transcript(
                            BrokerProtocolVersion::current(),
                            pending.pairing_request_id(),
                            consumer_id,
                            &public_key,
                            pending.client_nonce(),
                            pending.server_nonce(),
                        ));
                        match self.request(BrokerRequest::PairingComplete(
                            BrokerPairingCompleteRequest::new(pending.pairing_request_id(), proof),
                        ))? {
                            BrokerResponse::PairingComplete(completion)
                                if completion.consumer_id() == consumer_id =>
                            {
                                consumer_id
                            }
                            _ => return Err(BrokerAdapterError::Protocol),
                        }
                    }
                }
            }
            _ => return Err(BrokerAdapterError::Protocol),
        };

        let challenge = match self.request(BrokerRequest::AuthenticationStart(
            BrokerAuthenticationStartRequest::new(consumer_id),
        ))? {
            BrokerResponse::AuthenticationChallenge(challenge)
                if challenge.consumer_id() == consumer_id =>
            {
                challenge
            }
            _ => return Err(BrokerAdapterError::Protocol),
        };
        let session_id = challenge.session_id();
        let proof = identity.sign(&broker_authentication_transcript(
            BrokerProtocolVersion::current(),
            session_id,
            consumer_id,
            &public_key,
            challenge.broker_nonce(),
        ));
        match self.request(BrokerRequest::AuthenticationComplete(
            BrokerAuthenticationCompleteRequest::new(session_id, consumer_id, proof),
        ))? {
            BrokerResponse::Authenticated(authentication)
                if authentication.session_id() == session_id
                    && authentication.consumer_id() == consumer_id =>
            {
                self.authenticated_session = Some((session_id, consumer_id));
                Ok(BrokerAuthenticationStatus::Authenticated)
            }
            _ => Err(BrokerAdapterError::Protocol),
        }
    }

    pub(crate) fn execute(
        &mut self,
        request: BrokerRequest,
    ) -> Result<BrokerResponse, BrokerAdapterError> {
        if self.authenticated_session.is_none() || request.required_capability().is_none() {
            return Err(BrokerAdapterError::Protocol);
        }
        self.request(request)
    }

    pub(crate) fn status(
        &mut self,
    ) -> Result<psw_broker::BrokerStatusResponse, BrokerAdapterError> {
        self.negotiate()?;
        match self.request(BrokerRequest::Status)? {
            BrokerResponse::Status(status) => Ok(status),
            _ => Err(BrokerAdapterError::Protocol),
        }
    }

    fn negotiate(&mut self) -> Result<(), BrokerAdapterError> {
        if self.negotiated {
            return Ok(());
        }
        let response = self.request(BrokerRequest::Hello(
            BrokerHelloRequest::new(
                vec![BrokerProtocolVersionRange::new(
                    BrokerProtocolVersion::current().major(),
                    BrokerProtocolVersion::current().minor(),
                    BrokerProtocolVersion::current().minor(),
                )
                .map_err(|_| BrokerAdapterError::Protocol)?],
                [
                    CapabilityName::CredentialSearch,
                    CapabilityName::AccessRequest,
                    CapabilityName::GrantStatus,
                    CapabilityName::GrantRevoke,
                    CapabilityName::HttpRequest,
                    CapabilityName::ProcessRun,
                ]
                .into_iter()
                .map(|name| psw_broker::BrokerCapabilityVersions::new(name, [1]))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| BrokerAdapterError::Protocol)?,
            )
            .map_err(|_| BrokerAdapterError::Protocol)?,
        ))?;
        match response {
            BrokerResponse::Hello(hello)
                if hello.selected_protocol() == BrokerProtocolVersion::current()
                    && [
                        CapabilityName::CredentialSearch,
                        CapabilityName::AccessRequest,
                        CapabilityName::GrantStatus,
                        CapabilityName::GrantRevoke,
                        CapabilityName::HttpRequest,
                        CapabilityName::ProcessRun,
                    ]
                    .iter()
                    .all(|expected| {
                        hello.capabilities().iter().any(|selected| {
                            selected.capability_name() == *expected && selected.version() == 1
                        })
                    })
                    && hello.capabilities().len() == 6 =>
            {
                self.negotiated = true;
                Ok(())
            }
            _ => Err(BrokerAdapterError::Protocol),
        }
    }

    fn request(&mut self, request: BrokerRequest) -> Result<BrokerResponse, BrokerAdapterError> {
        let request_id = BrokerRequestId::generate();
        let envelope =
            BrokerRequestEnvelope::new(BrokerProtocolVersion::current(), request_id, request);
        let payload = encode_broker_request(&envelope).map_err(|_| BrokerAdapterError::Protocol)?;
        write_broker_frame(&mut self.stream, &payload)
            .and_then(|()| {
                self.stream
                    .flush()
                    .map_err(|_| psw_broker::BrokerFrameError::Write)
            })
            .map_err(|_| BrokerAdapterError::Transport)?;
        let response_payload = read_broker_frame(&mut self.stream)
            .map_err(|_| BrokerAdapterError::Transport)?
            .ok_or(BrokerAdapterError::Transport)?;
        let response =
            decode_broker_response(&response_payload).map_err(|_| BrokerAdapterError::Protocol)?;
        if response.request_id() != request_id
            || response.version() != BrokerProtocolVersion::current()
        {
            return Err(BrokerAdapterError::Protocol);
        }
        match response.response() {
            BrokerResponse::Error(error) => Err(BrokerAdapterError::Broker {
                error_code: error.error_code(),
                retryable: error.retryable(),
                required_action: error.required_action(),
                approval_request_id: error.approval_request_id(),
            }),
            response => Ok(response.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{self, Cursor};

    use ed25519_dalek::{Signature, VerifyingKey};
    use psw_broker::decode_broker_request;
    use serde_json::json;

    use super::*;

    #[derive(Clone, Copy)]
    enum EnvelopeFault {
        RequestId,
        ProtocolMinor,
    }

    struct ScriptedBroker {
        read_bytes: VecDeque<u8>,
        written: Vec<u8>,
        stage: usize,
        hello_result: serde_json::Value,
        expected_public_key: [u8; 32],
        consumer_id: ConsumerId,
        session_id: BrokerSessionId,
        broker_instance_id: psw_broker::BrokerInstanceId,
        broker_nonce: [u8; psw_broker::AUTHENTICATION_NONCE_LENGTH],
        envelope_fault: Option<(usize, EnvelopeFault)>,
    }

    impl ScriptedBroker {
        fn new(expected_public_key: [u8; 32]) -> Self {
            Self::with_hello_result(
                expected_public_key,
                json!({
                    "selected_protocol": {"major": 1, "minor": 0},
                    "capabilities": [
                        {"capability_name": "credential.search", "version": 1},
                        {"capability_name": "access.request", "version": 1},
                        {"capability_name": "grant.status", "version": 1},
                        {"capability_name": "grant.revoke", "version": 1},
                        {"capability_name": "http.request", "version": 1},
                        {"capability_name": "process.run", "version": 1}
                    ]
                }),
            )
        }

        fn with_hello_result(
            expected_public_key: [u8; 32],
            hello_result: serde_json::Value,
        ) -> Self {
            Self {
                read_bytes: VecDeque::new(),
                written: Vec::new(),
                stage: 0,
                hello_result,
                expected_public_key,
                consumer_id: ConsumerId::generate(),
                session_id: BrokerSessionId::generate(),
                broker_instance_id: psw_broker::BrokerInstanceId::generate(),
                broker_nonce: [0x82; psw_broker::AUTHENTICATION_NONCE_LENGTH],
                envelope_fault: None,
            }
        }

        fn with_envelope_fault(
            expected_public_key: [u8; 32],
            stage: usize,
            fault: EnvelopeFault,
        ) -> Self {
            let mut broker = Self::new(expected_public_key);
            broker.envelope_fault = Some((stage, fault));
            broker
        }

        fn respond(&mut self) -> io::Result<()> {
            let mut input = Cursor::new(std::mem::take(&mut self.written));
            let payload = read_broker_frame(&mut input)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request frame"))?
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "request"))?;
            let request = decode_broker_request(&payload)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request protocol"))?;
            let request_id = request.request_id().to_string();
            let response_request_id = if matches!(
                self.envelope_fault,
                Some((stage, EnvelopeFault::RequestId)) if stage == self.stage
            ) {
                BrokerRequestId::generate().to_string()
            } else {
                request_id
            };
            let response_protocol_minor = if matches!(
                self.envelope_fault,
                Some((stage, EnvelopeFault::ProtocolMinor)) if stage == self.stage
            ) {
                BrokerProtocolVersion::current().minor() + 1
            } else {
                BrokerProtocolVersion::current().minor()
            };
            let response = match (self.stage, request.request()) {
                (0, BrokerRequest::Hello(_)) => json!({
                    "protocol_name": "keptnear.broker",
                    "protocol_major": 1,
                    "protocol_minor": response_protocol_minor,
                    "message_type": "hello.result",
                    "request_id": response_request_id,
                    "result": self.hello_result.clone()
                }),
                (1, BrokerRequest::Status) => json!({
                    "protocol_name": "keptnear.broker",
                    "protocol_major": 1,
                    "protocol_minor": response_protocol_minor,
                    "message_type": "broker.status.result",
                    "request_id": response_request_id,
                    "result": {
                        "broker_instance_id": self.broker_instance_id.to_string()
                    }
                }),
                (1, BrokerRequest::PairingStart(_)) => {
                    let BrokerRequest::PairingStart(pairing) = request.request() else {
                        unreachable!()
                    };
                    if pairing.pairing_public_key() != &self.expected_public_key {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "public key"));
                    }
                    json!({
                        "protocol_name": "keptnear.broker",
                        "protocol_major": 1,
                        "protocol_minor": response_protocol_minor,
                        "message_type": "consumer.pair.result",
                        "request_id": response_request_id,
                        "result": {
                            "status": "active",
                            "consumer_id": self.consumer_id.to_string()
                        }
                    })
                }
                (2, BrokerRequest::AuthenticationStart(authentication))
                    if authentication.consumer_id() == self.consumer_id =>
                {
                    json!({
                        "protocol_name": "keptnear.broker",
                        "protocol_major": 1,
                        "protocol_minor": response_protocol_minor,
                        "message_type": "consumer.auth.challenge",
                        "request_id": response_request_id,
                        "result": {
                            "session_id": self.session_id.to_string(),
                            "consumer_id": self.consumer_id.to_string(),
                            "broker_nonce": encode_hex(&self.broker_nonce),
                            "valid_for_seconds": 30
                        }
                    })
                }
                (3, BrokerRequest::AuthenticationComplete(authentication))
                    if authentication.session_id() == self.session_id
                        && authentication.consumer_id() == self.consumer_id =>
                {
                    let transcript = broker_authentication_transcript(
                        BrokerProtocolVersion::current(),
                        self.session_id,
                        self.consumer_id,
                        &self.expected_public_key,
                        &self.broker_nonce,
                    );
                    let key = VerifyingKey::from_bytes(&self.expected_public_key)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "key"))?;
                    key.verify_strict(&transcript, &Signature::from_bytes(authentication.proof()))
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "proof"))?;
                    json!({
                        "protocol_name": "keptnear.broker",
                        "protocol_major": 1,
                        "protocol_minor": response_protocol_minor,
                        "message_type": "consumer.auth.result",
                        "request_id": response_request_id,
                        "result": {
                            "session_id": self.session_id.to_string(),
                            "consumer_id": self.consumer_id.to_string()
                        }
                    })
                }
                _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "request order")),
            };
            self.stage += 1;
            let payload = serde_json::to_vec(&response)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response"))?;
            let mut frame = Vec::new();
            write_broker_frame(&mut frame, &payload)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response frame"))?;
            self.read_bytes.extend(frame);
            Ok(())
        }
    }

    impl Read for ScriptedBroker {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let count = output.len().min(self.read_bytes.len());
            for byte in output.iter_mut().take(count) {
                *byte = self.read_bytes.pop_front().expect("queued byte");
            }
            Ok(count)
        }
    }

    impl Write for ScriptedBroker {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.respond()
        }
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    #[test]
    fn client_negotiates_and_signs_the_exact_broker_authentication_transcript() {
        let identity = ConsumerIdentity::from_stored_bytes(vec![0x81; 32]).expect("identity");
        let stream = ScriptedBroker::new(identity.public_key());
        let mut client = BrokerClient::new(stream);

        assert_eq!(
            client.authenticate(&identity).expect("authenticate"),
            BrokerAuthenticationStatus::Authenticated
        );
        assert_eq!(
            client.authenticate(&identity).expect("cached session"),
            BrokerAuthenticationStatus::Authenticated
        );
        assert_eq!(client.stream.stage, 4);
    }

    #[test]
    fn status_negotiates_without_pairing_or_authentication() {
        let identity = ConsumerIdentity::from_stored_bytes(vec![0x84; 32]).expect("identity");
        let stream = ScriptedBroker::new(identity.public_key());
        let expected_instance_id = stream.broker_instance_id;
        let mut client = BrokerClient::new(stream);

        assert_eq!(
            client.status().expect("status").broker_instance_id(),
            expected_instance_id
        );
        assert_eq!(client.stream.stage, 2);
        assert!(client.authenticated_session.is_none());
    }

    #[test]
    fn client_rejects_incomplete_or_version_mismatched_broker_capabilities() {
        let identity = ConsumerIdentity::from_stored_bytes(vec![0x83; 32]).expect("identity");
        let incomplete = json!({
            "selected_protocol": {"major": 1, "minor": 0},
            "capabilities": [
                {"capability_name": "credential.search", "version": 1},
                {"capability_name": "access.request", "version": 1},
                {"capability_name": "grant.status", "version": 1},
                {"capability_name": "grant.revoke", "version": 1},
                {"capability_name": "http.request", "version": 1}
            ]
        });
        let wrong_version = json!({
            "selected_protocol": {"major": 1, "minor": 0},
            "capabilities": [
                {"capability_name": "credential.search", "version": 1},
                {"capability_name": "access.request", "version": 1},
                {"capability_name": "grant.status", "version": 1},
                {"capability_name": "grant.revoke", "version": 1},
                {"capability_name": "http.request", "version": 1},
                {"capability_name": "process.run", "version": 2}
            ]
        });

        for hello_result in [incomplete, wrong_version] {
            let stream = ScriptedBroker::with_hello_result(identity.public_key(), hello_result);
            let mut client = BrokerClient::new(stream);
            assert_eq!(
                client.authenticate(&identity),
                Err(BrokerAdapterError::Protocol)
            );
            assert_eq!(client.stream.stage, 1);
        }
    }

    #[test]
    fn client_rejects_mismatched_response_identity_and_protocol_revision() {
        let identity = ConsumerIdentity::from_stored_bytes(vec![0x85; 32]).expect("identity");
        for fault in [EnvelopeFault::RequestId, EnvelopeFault::ProtocolMinor] {
            let stream = ScriptedBroker::with_envelope_fault(identity.public_key(), 1, fault);
            let mut client = BrokerClient::new(stream);
            assert_eq!(client.status(), Err(BrokerAdapterError::Protocol));
            assert_eq!(client.stream.stage, 2);
        }
    }
}
