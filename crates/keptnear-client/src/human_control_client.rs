use std::fmt::{Display, Formatter};
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use psw_broker::{
    decode_human_control_response, encode_human_control_request, read_human_control_frame,
    write_human_control_frame, ControllerAuthenticationChallenge, ControllerAuthenticationProof,
    ControllerChallengeRequest, ControllerId, ControllerNonce, ControllerSessionId,
    ControllerSigningKey, HumanControlClientResponse, HumanControlFailureCode,
    HumanControlOperation, HumanControlProtocolVersion, HumanControlProtocolVersionRange,
    HumanControlRequest, HumanControlRequestId, HumanControlRequiredAction,
    HumanControlSuccessEnvelope, HumanControlVersionOffer, CONTROLLER_ROLE,
    HUMAN_CONTROL_CONTROLLER_LEASE_TTL, HUMAN_CONTROL_SCHEMA_ID,
};

/// Minimal proof boundary required by the Human Control client.
///
/// Implementations retain ownership of signing material and return only public
/// identity fields plus the challenge-bound proof sent to the local Broker.
pub trait HumanControlSigner {
    /// Returns the stable controller identity derived from the public key.
    fn controller_id(&self) -> ControllerId;
    /// Returns the public Ed25519 verification key.
    fn public_key(&self) -> [u8; 32];
    /// Signs exactly one validated Broker challenge.
    fn prove(&self, challenge: &ControllerAuthenticationChallenge)
        -> ControllerAuthenticationProof;
}

impl HumanControlSigner for ControllerSigningKey {
    fn controller_id(&self) -> ControllerId {
        self.controller_id()
    }

    fn public_key(&self) -> [u8; 32] {
        self.public_key()
    }

    fn prove(
        &self,
        challenge: &ControllerAuthenticationChallenge,
    ) -> ControllerAuthenticationProof {
        challenge.prove(self)
    }
}

/// Sanitized Human Control client failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanControlClientError {
    /// The restricted controller signing key is absent or unavailable.
    ControllerUnavailable,
    /// Local framing, timeout, or stream I/O failed.
    Transport,
    /// A response violated the closed negotiated protocol.
    Protocol,
    /// The Broker returned one fixed localizable failure.
    Broker {
        /// Stable Human Control failure category.
        code: HumanControlFailureCode,
        /// Whether a bounded retry may succeed without another user decision.
        retryable: bool,
        /// Optional stable recovery action.
        required_action: Option<HumanControlRequiredAction>,
    },
}

impl Display for HumanControlClientError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ControllerUnavailable => "Human Control controller is unavailable",
            Self::Transport => "Human Control transport failed",
            Self::Protocol => "Human Control protocol failed",
            Self::Broker { .. } => "Human Control request was rejected",
        })
    }
}

impl std::error::Error for HumanControlClientError {}

/// Stream boundary that can tighten each blocking I/O wait to a remaining deadline.
pub trait HumanControlTransport: Read + Write {
    /// Applies the maximum wait for the next blocking stream operation.
    fn set_operation_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

#[cfg(unix)]
impl HumanControlTransport for std::os::unix::net::UnixStream {
    fn set_operation_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)?;
        self.set_write_timeout(timeout)
    }
}

/// Authenticated source-level Human Control client over one bounded local stream.
pub struct HumanControlClient<Stream> {
    stream: Stream,
    operation_timeout: Duration,
    selected_protocol: Option<HumanControlProtocolVersion>,
    broker_instance_id: Option<psw_broker::BrokerInstanceId>,
    authenticated_session: Option<(ControllerId, ControllerSessionId)>,
}

impl<Stream> HumanControlClient<Stream>
where
    Stream: HumanControlTransport,
{
    /// Creates a lazy client without reading a key or contacting a Broker.
    #[must_use]
    pub const fn new(stream: Stream, operation_timeout: Duration) -> Self {
        Self {
            stream,
            operation_timeout,
            selected_protocol: None,
            broker_instance_id: None,
            authenticated_session: None,
        }
    }

    /// Negotiates and proves possession of one injected controller signing key.
    pub fn authenticate<S: HumanControlSigner + ?Sized>(
        &mut self,
        signing_key: &S,
    ) -> Result<(), HumanControlClientError> {
        if matches!(self.authenticated_session, Some((controller_id, _)) if controller_id == signing_key.controller_id())
        {
            return self.renew_lease().map(|_| ());
        }
        let (selected, broker_instance_id) = match (
            self.selected_protocol,
            self.broker_instance_id,
            self.authenticated_session,
        ) {
            (Some(selected), Some(broker_instance_id), None) => (selected, broker_instance_id),
            (None, None, None) => self.negotiate()?,
            _ => return Err(HumanControlClientError::Protocol),
        };

        let client_nonce = ControllerNonce::generate();
        let challenge_request =
            ControllerChallengeRequest::new(signing_key.controller_id(), client_nonce);
        let challenge_response =
            self.request(HumanControlRequest::ControllerChallenge(challenge_request))?;
        let challenge = challenge_response
            .controller_challenge()
            .map_err(|_| HumanControlClientError::Protocol)?;
        if challenge.protocol() != selected
            || challenge.broker_instance_id() != broker_instance_id
            || challenge.controller_id() != signing_key.controller_id()
            || challenge.public_key() != signing_key.public_key()
            || challenge.client_nonce() != client_nonce
        {
            return Err(HumanControlClientError::Protocol);
        }
        let authenticated = self.request(HumanControlRequest::ControllerAuthenticate(
            signing_key.prove(&challenge),
        ))?;
        let (controller_id, session_id, lease_duration_millis) = authenticated
            .authenticated_session()
            .map_err(|_| HumanControlClientError::Protocol)?;
        if controller_id != signing_key.controller_id()
            || session_id != challenge.session_id()
            || lease_duration_millis != controller_lease_duration_millis()
        {
            return Err(HumanControlClientError::Protocol);
        }
        self.authenticated_session = Some((controller_id, session_id));
        Ok(())
    }

    fn negotiate(
        &mut self,
    ) -> Result<(HumanControlProtocolVersion, psw_broker::BrokerInstanceId), HumanControlClientError>
    {
        self.negotiate_with_current(HumanControlProtocolVersion::current())
    }

    fn negotiate_with_current(
        &mut self,
        current: HumanControlProtocolVersion,
    ) -> Result<(HumanControlProtocolVersion, psw_broker::BrokerInstanceId), HumanControlClientError>
    {
        let offer = HumanControlVersionOffer::new(
            CONTROLLER_ROLE,
            [
                HumanControlProtocolVersionRange::new(current.major(), 0, current.minor())
                    .map_err(|_| HumanControlClientError::Protocol)?,
            ],
            [HUMAN_CONTROL_SCHEMA_ID.to_owned()],
        )
        .map_err(|_| HumanControlClientError::Protocol)?;
        let baseline = HumanControlProtocolVersion::new(current.major(), 0)
            .map_err(|_| HumanControlClientError::Protocol)?;
        let hello =
            self.request_with_versions(baseline, current, HumanControlRequest::Hello(offer))?;
        let (selected, schema, broker_instance_id) = hello
            .hello_selection()
            .map_err(|_| HumanControlClientError::Protocol)?;
        if !selected.is_supported_by(current)
            || schema != HUMAN_CONTROL_SCHEMA_ID
            || !hello.has_complete_operation_catalog()
        {
            return Err(HumanControlClientError::Protocol);
        }
        self.selected_protocol = Some(selected);
        self.broker_instance_id = Some(broker_instance_id);
        Ok((selected, broker_instance_id))
    }

    /// Executes one authenticated Human Control request.
    pub fn execute(
        &mut self,
        request: HumanControlRequest,
    ) -> Result<HumanControlSuccessEnvelope, HumanControlClientError> {
        if self.authenticated_session.is_none()
            || matches!(
                request.operation(),
                HumanControlOperation::Hello
                    | HumanControlOperation::ControllerChallenge
                    | HumanControlOperation::ControllerAuthenticate
            )
        {
            return Err(HumanControlClientError::Protocol);
        }
        self.request(request)
    }

    /// Renews the current authenticated connection lease.
    pub fn renew_lease(&mut self) -> Result<u64, HumanControlClientError> {
        let (_, session_id) = self
            .authenticated_session
            .ok_or(HumanControlClientError::Protocol)?;
        let broker_instance_id = self
            .broker_instance_id
            .ok_or(HumanControlClientError::Protocol)?;
        let response = self.request(HumanControlRequest::ControllerLeaseRenew {
            controller_session_id: session_id,
            broker_instance_id,
        })?;
        let (response_session_id, lease_duration_millis) = response
            .controller_lease()
            .map_err(|_| HumanControlClientError::Protocol)?;
        if response_session_id != session_id
            || lease_duration_millis != controller_lease_duration_millis()
        {
            return Err(HumanControlClientError::Protocol);
        }
        Ok(lease_duration_millis)
    }

    fn request(
        &mut self,
        request: HumanControlRequest,
    ) -> Result<HumanControlSuccessEnvelope, HumanControlClientError> {
        let version = self
            .selected_protocol
            .ok_or(HumanControlClientError::Protocol)?;
        self.request_with_version(version, request)
    }

    fn request_with_version(
        &mut self,
        version: HumanControlProtocolVersion,
        request: HumanControlRequest,
    ) -> Result<HumanControlSuccessEnvelope, HumanControlClientError> {
        self.request_with_versions(version, version, request)
    }

    fn request_with_versions(
        &mut self,
        request_version: HumanControlProtocolVersion,
        maximum_response_version: HumanControlProtocolVersion,
        request: HumanControlRequest,
    ) -> Result<HumanControlSuccessEnvelope, HumanControlClientError> {
        let request_id = HumanControlRequestId::generate();
        let operation = request.operation();
        let payload = encode_human_control_request(request_id, request_version, &request)
            .map_err(|_| HumanControlClientError::Protocol)?;
        let deadline = Instant::now()
            .checked_add(self.operation_timeout)
            .ok_or(HumanControlClientError::Transport)?;
        let mut transport = DeadlineTransport::new(&mut self.stream, deadline);
        write_human_control_frame(&mut transport, payload.as_bytes())
            .map_err(|_| HumanControlClientError::Transport)?;
        let response = read_human_control_frame(&mut transport)
            .map_err(|_| HumanControlClientError::Transport)?
            .ok_or(HumanControlClientError::Transport)?;
        match decode_human_control_response(
            response.as_bytes(),
            request_id,
            maximum_response_version,
            operation,
        )
        .map_err(|_| HumanControlClientError::Protocol)?
        {
            HumanControlClientResponse::Success(response) => Ok(response),
            HumanControlClientResponse::Failure(failure) => Err(HumanControlClientError::Broker {
                code: failure.code(),
                retryable: failure.retryable(),
                required_action: failure.required_action(),
            }),
        }
    }
}

struct DeadlineTransport<'a, Stream> {
    stream: &'a mut Stream,
    deadline: Instant,
}

impl<'a, Stream> DeadlineTransport<'a, Stream> {
    const fn new(stream: &'a mut Stream, deadline: Instant) -> Self {
        Self { stream, deadline }
    }
}

impl<Stream: HumanControlTransport> DeadlineTransport<'_, Stream> {
    fn apply_remaining_timeout(&self) -> io::Result<()> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "operation deadline"))?;
        self.stream.set_operation_timeout(Some(remaining))
    }
}

impl<Stream: HumanControlTransport> Read for DeadlineTransport<'_, Stream> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.apply_remaining_timeout()?;
        self.stream.read(buffer)
    }
}

impl<Stream: HumanControlTransport> Write for DeadlineTransport<'_, Stream> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.apply_remaining_timeout()?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.apply_remaining_timeout()?;
        self.stream.flush()
    }
}

fn controller_lease_duration_millis() -> u64 {
    u64::try_from(HUMAN_CONTROL_CONTROLLER_LEASE_TTL.as_millis())
        .expect("the frozen Human Control lease fits u64 milliseconds")
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{self, Cursor};

    use ed25519_dalek::{Signer, SigningKey};
    use psw_broker::{
        decode_human_control_hello_wire_envelope, decode_human_control_wire_envelope,
        encode_human_control_failure, encode_human_control_response, read_human_control_frame,
        BrokerInstanceId, ControllerAuthenticationChallenge, ControllerAuthenticationMode,
        ControllerAuthenticationProof, ControllerDeadline, ControllerSignature, HumanControlLimits,
        HumanControlProtocolFailure, HumanControlResponse, HumanControlWireEnvelope,
        StateTimestamp, HUMAN_CONTROL_OPERATION_CONTRACTS,
    };

    use super::*;

    struct TestSigner {
        key: SigningKey,
    }

    impl TestSigner {
        fn new(seed_byte: u8) -> Self {
            Self {
                key: SigningKey::from_bytes(&[seed_byte; 32]),
            }
        }
    }

    impl HumanControlSigner for TestSigner {
        fn controller_id(&self) -> ControllerId {
            ControllerId::from_bytes(psw_broker::derive_controller_id(&self.public_key()))
        }

        fn public_key(&self) -> [u8; 32] {
            self.key.verifying_key().to_bytes()
        }

        fn prove(
            &self,
            challenge: &ControllerAuthenticationChallenge,
        ) -> ControllerAuthenticationProof {
            ControllerAuthenticationProof::from_validated_wire_bindings(
                challenge.broker_instance_id(),
                challenge.controller_id(),
                challenge.session_id(),
                challenge.client_nonce(),
                challenge.broker_nonce(),
                challenge.deadline(),
                ControllerSignature::from_bytes(self.key.sign(&challenge.transcript()).to_bytes()),
            )
        }
    }

    #[derive(Clone, Copy)]
    enum ScriptFault {
        None,
        WrongRequestId,
        WrongPublicKey,
        WrongClientNonce,
        WrongAuthenticatedSession,
        WrongAuthenticatedLease,
        WrongRenewedLease,
        FixedFailure,
        Eof,
    }

    struct ScriptedHumanControlBroker {
        read_bytes: VecDeque<u8>,
        written: Vec<u8>,
        stage: usize,
        key: TestSigner,
        broker_instance_id: BrokerInstanceId,
        session_id: ControllerSessionId,
        challenge: Option<ControllerAuthenticationChallenge>,
        fault: ScriptFault,
    }

    impl ScriptedHumanControlBroker {
        fn new(seed_byte: u8, fault: ScriptFault) -> Self {
            Self {
                read_bytes: VecDeque::new(),
                written: Vec::new(),
                stage: 0,
                key: TestSigner::new(seed_byte),
                broker_instance_id: BrokerInstanceId::generate(),
                session_id: ControllerSessionId::from_bytes([0x61; 16]),
                challenge: None,
                fault,
            }
        }

        fn respond(&mut self) -> io::Result<()> {
            if matches!(self.fault, ScriptFault::Eof) {
                self.written.clear();
                return Ok(());
            }
            let mut input = Cursor::new(std::mem::take(&mut self.written));
            let payload = read_human_control_frame(&mut input)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request frame"))?
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "request"))?;
            let envelope = if self.stage == 0 {
                decode_human_control_hello_wire_envelope(payload)
            } else {
                decode_human_control_wire_envelope(payload, HumanControlProtocolVersion::current())
            }
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request protocol"))?;
            let request_id = if matches!(self.fault, ScriptFault::WrongRequestId) && self.stage == 1
            {
                HumanControlRequestId::from_bytes([0x62; 16])
            } else {
                envelope.request_id()
            };

            let encoded = if matches!(self.fault, ScriptFault::FixedFailure) && self.stage == 1 {
                encode_human_control_failure(
                    request_id,
                    HumanControlProtocolVersion::current(),
                    HumanControlProtocolFailure::new(
                        HumanControlFailureCode::RateLimited,
                        true,
                        Some(HumanControlRequiredAction::RetryLater),
                    ),
                )
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "failure"))?
            } else {
                let response = self.response_for(&envelope)?;
                encode_human_control_response(
                    request_id,
                    HumanControlProtocolVersion::current(),
                    envelope.operation(),
                    &response,
                )
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response"))?
            };
            self.stage += 1;
            let mut frame = Vec::new();
            write_human_control_frame(&mut frame, &encoded)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response frame"))?;
            self.read_bytes.extend(frame);
            Ok(())
        }

        fn response_for(
            &mut self,
            envelope: &HumanControlWireEnvelope,
        ) -> io::Result<HumanControlResponse> {
            match envelope
                .to_typed_request(StateTimestamp::from_unix_millis(10).expect("timestamp"))
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "typed request"))?
            {
                HumanControlRequest::Hello(_) => Ok(HumanControlResponse::Hello {
                    protocol: HumanControlProtocolVersion::current(),
                    schema: HUMAN_CONTROL_SCHEMA_ID,
                    broker_instance_id: self.broker_instance_id,
                    limits: HumanControlLimits::current(),
                    operations: HUMAN_CONTROL_OPERATION_CONTRACTS
                        .iter()
                        .map(|contract| contract.operation())
                        .collect(),
                }),
                HumanControlRequest::ControllerChallenge(request) => {
                    let public_key = if matches!(self.fault, ScriptFault::WrongPublicKey) {
                        [0x63; 32]
                    } else {
                        self.key.public_key()
                    };
                    let controller_id = if matches!(self.fault, ScriptFault::WrongPublicKey) {
                        ControllerId::from_bytes(psw_broker::derive_controller_id(&public_key))
                    } else {
                        request.controller_id()
                    };
                    let client_nonce = if matches!(self.fault, ScriptFault::WrongClientNonce) {
                        ControllerNonce::from_bytes([0x65; 32])
                    } else {
                        request.client_nonce()
                    };
                    let challenge =
                        ControllerAuthenticationChallenge::from_validated_wire_bindings(
                            ControllerAuthenticationMode::Authenticate,
                            HumanControlProtocolVersion::current(),
                            self.broker_instance_id,
                            controller_id,
                            public_key,
                            self.session_id,
                            client_nonce,
                            ControllerNonce::from_bytes([0x64; 32]),
                            ControllerDeadline::new(1).expect("deadline"),
                        )
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "challenge"))?;
                    self.challenge = Some(challenge.clone());
                    Ok(HumanControlResponse::ControllerChallenge(challenge))
                }
                HumanControlRequest::ControllerAuthenticate(proof) => {
                    let challenge = self.challenge.as_ref().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "missing challenge")
                    })?;
                    let expected = self.key.prove(challenge);
                    if expected != proof {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "proof"));
                    }
                    let session_id = if matches!(self.fault, ScriptFault::WrongAuthenticatedSession)
                    {
                        ControllerSessionId::from_bytes([0x66; 16])
                    } else {
                        self.session_id
                    };
                    let lease_duration_millis =
                        if matches!(self.fault, ScriptFault::WrongAuthenticatedLease) {
                            1
                        } else {
                            controller_lease_duration_millis()
                        };
                    Ok(HumanControlResponse::ControllerAuthenticated {
                        controller_id: self.key.controller_id(),
                        session_id,
                        lease_duration_millis,
                    })
                }
                HumanControlRequest::ControllerLeaseRenew {
                    controller_session_id,
                    broker_instance_id,
                } if controller_session_id == self.session_id
                    && broker_instance_id == self.broker_instance_id =>
                {
                    Ok(HumanControlResponse::ControllerLease {
                        session_id: self.session_id,
                        lease_duration_millis: if matches!(
                            self.fault,
                            ScriptFault::WrongRenewedLease
                        ) {
                            1
                        } else {
                            controller_lease_duration_millis()
                        },
                    })
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected request",
                )),
            }
        }
    }

    impl Read for ScriptedHumanControlBroker {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let count = output.len().min(self.read_bytes.len());
            for byte in output.iter_mut().take(count) {
                *byte = self.read_bytes.pop_front().expect("queued byte");
            }
            Ok(count)
        }
    }

    impl Write for ScriptedHumanControlBroker {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.respond()
        }
    }

    impl HumanControlTransport for ScriptedHumanControlBroker {
        fn set_operation_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    const TEST_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);

    fn signing_key(seed_byte: u8) -> TestSigner {
        TestSigner::new(seed_byte)
    }

    #[test]
    fn client_negotiates_authenticates_and_renews_the_exact_controller_session() {
        let key = signing_key(0x51);
        let stream = ScriptedHumanControlBroker::new(0x51, ScriptFault::None);
        let mut client = HumanControlClient::new(stream, TEST_OPERATION_TIMEOUT);

        client.authenticate(&key).expect("authenticate");
        assert_eq!(client.renew_lease().expect("renew"), 30_000);
        assert_eq!(client.stream.stage, 4);
        client.authenticate(&key).expect("cached authentication");
        assert_eq!(client.stream.stage, 5);
    }

    #[test]
    fn client_maps_only_fixed_broker_failures() {
        let key = signing_key(0x52);
        let stream = ScriptedHumanControlBroker::new(0x52, ScriptFault::FixedFailure);
        let mut client = HumanControlClient::new(stream, TEST_OPERATION_TIMEOUT);

        assert_eq!(
            client.authenticate(&key),
            Err(HumanControlClientError::Broker {
                code: HumanControlFailureCode::RateLimited,
                retryable: true,
                required_action: Some(HumanControlRequiredAction::RetryLater),
            })
        );
    }

    #[test]
    fn client_rejects_response_identity_and_controller_key_mismatch() {
        for fault in [
            ScriptFault::WrongRequestId,
            ScriptFault::WrongPublicKey,
            ScriptFault::WrongClientNonce,
            ScriptFault::WrongAuthenticatedSession,
            ScriptFault::WrongAuthenticatedLease,
        ] {
            let key = signing_key(0x53);
            let stream = ScriptedHumanControlBroker::new(0x53, fault);
            let mut client = HumanControlClient::new(stream, TEST_OPERATION_TIMEOUT);
            assert_eq!(
                client.authenticate(&key),
                Err(HumanControlClientError::Protocol)
            );
        }
    }

    #[test]
    fn client_rejects_drifted_renewal_lease() {
        let key = signing_key(0x56);
        let stream = ScriptedHumanControlBroker::new(0x56, ScriptFault::WrongRenewedLease);
        let mut client = HumanControlClient::new(stream, TEST_OPERATION_TIMEOUT);

        client.authenticate(&key).expect("authenticate");
        assert_eq!(client.renew_lease(), Err(HumanControlClientError::Protocol));
    }

    #[test]
    fn client_maps_peer_eof_to_transport_without_internal_detail() {
        let key = signing_key(0x54);
        let stream = ScriptedHumanControlBroker::new(0x54, ScriptFault::Eof);
        let mut client = HumanControlClient::new(stream, TEST_OPERATION_TIMEOUT);
        let error = client.authenticate(&key).expect_err("transport failure");
        assert_eq!(error, HumanControlClientError::Transport);
        assert_eq!(error.to_string(), "Human Control transport failed");
    }

    #[cfg(unix)]
    #[test]
    fn client_maps_a_bounded_read_wait_to_transport() {
        use std::os::unix::net::UnixStream;

        let key = signing_key(0x55);
        let (stream, _silent_peer) = UnixStream::pair().expect("socket pair");
        let mut client = HumanControlClient::new(stream, Duration::from_millis(100));
        let started = Instant::now();

        assert_eq!(
            client.authenticate(&key),
            Err(HumanControlClientError::Transport)
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn client_offers_every_compatible_minor_and_accepts_an_older_broker() {
        let future_client = HumanControlProtocolVersion::new(1, 1).expect("future client");
        let stream = ScriptedHumanControlBroker::new(0x57, ScriptFault::None);
        let mut client = HumanControlClient::new(stream, TEST_OPERATION_TIMEOUT);

        let (selected, _) = client
            .negotiate_with_current(future_client)
            .expect("compatible downgrade");

        assert_eq!(selected, HumanControlProtocolVersion::current());
        assert_eq!(client.stream.stage, 1);
    }

    #[cfg(unix)]
    #[test]
    fn client_bounds_the_entire_frame_exchange_against_a_trickling_peer() {
        use std::os::unix::net::UnixStream;
        use std::thread;

        let key = signing_key(0x58);
        let (stream, mut trickling_peer) = UnixStream::pair().expect("socket pair");
        let peer = thread::spawn(move || {
            let declared_payload_length = 64_u32.to_be_bytes();
            for byte in declared_payload_length
                .into_iter()
                .chain(std::iter::repeat_n(b'x', 64))
            {
                thread::sleep(Duration::from_millis(40));
                if trickling_peer.write_all(&[byte]).is_err() {
                    break;
                }
            }
        });
        let mut client = HumanControlClient::new(stream, Duration::from_millis(120));
        let started = Instant::now();

        assert_eq!(
            client.authenticate(&key),
            Err(HumanControlClientError::Transport)
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        drop(client);
        peer.join().expect("trickling peer");
    }
}
