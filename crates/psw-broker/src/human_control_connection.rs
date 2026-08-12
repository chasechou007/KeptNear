use std::fmt::{Display, Formatter};
use std::io::{self, Cursor, Read, Write};
use std::ops::{Deref, DerefMut};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use zeroize::Zeroizing;

use crate::{
    decode_human_control_hello_wire_envelope, decode_human_control_wire_envelope,
    encode_human_control_failure, encode_human_control_response, read_human_control_frame,
    write_human_control_frame, BrokerConnectionExit, BrokerProcessError,
    BrokerProcessRunCancellation, BrokerRuntime, ControllerKeyStore, HumanControlConnectionPhase,
    HumanControlDispatcher, HumanControlFailureCode, HumanControlFrame, HumanControlOperation,
    HumanControlProtocolFailure, HumanControlProtocolVersion, HumanControlWireError,
    ObservedConsumerIdentity, StateTimestamp, BROKER_PROTOCOL_NAME, HUMAN_CONTROL_PROTOCOL_NAME,
    MAX_BROKER_HELLO_LENGTH,
};

/// Connection class selected from one bounded, duplicate-free first frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerConnectionClass {
    /// Existing paired Consumer protocol.
    Consumer,
    /// Dedicated authenticated App Human Control protocol.
    HumanControl,
}

/// Sanitized failure while routing or serving one local Broker connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerConnectionRouteError {
    /// The initial frame was empty, truncated, oversized, or unreadable.
    InitialFrame,
    /// The initial JSON declared no exact supported connection class.
    UnknownProtocol,
    /// The existing Consumer process loop failed.
    Consumer(BrokerProcessError),
    /// Human Control framing, encoding, or output failed.
    HumanControl(HumanControlWireError),
    /// The wall clock could not produce a canonical dispatch timestamp.
    ClockUnavailable,
}

impl Display for BrokerConnectionRouteError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InitialFrame => "Broker connection first frame failed",
            Self::UnknownProtocol => "Broker connection protocol is unsupported",
            Self::Consumer(_) => "Broker Consumer connection failed",
            Self::HumanControl(_) => "Broker Human Control connection failed",
            Self::ClockUnavailable => "Broker connection clock is unavailable",
        })
    }
}

impl std::error::Error for BrokerConnectionRouteError {}

/// Serves one already-established stream through exactly one local protocol.
pub fn serve_routed_broker_connection<S>(
    runtime: &mut BrokerRuntime,
    dispatcher: &HumanControlDispatcher<S>,
    observed_identity: &ObservedConsumerIdentity,
    reader: &mut impl Read,
    writer: &mut impl Write,
    process_cancellation: &BrokerProcessRunCancellation,
) -> Result<(BrokerConnectionClass, BrokerConnectionExit), BrokerConnectionRouteError>
where
    S: ControllerKeyStore,
{
    let mut clocks = ConnectionClocks {
        monotonic_now: Instant::now,
        state_now: current_state_timestamp,
    };
    serve_routed_broker_connection_with_clocks(
        runtime,
        dispatcher,
        observed_identity,
        reader,
        writer,
        process_cancellation,
        &mut clocks,
    )
}

fn serve_routed_broker_connection_with_clocks<S, M, T>(
    runtime: &mut BrokerRuntime,
    dispatcher: &HumanControlDispatcher<S>,
    observed_identity: &ObservedConsumerIdentity,
    reader: &mut impl Read,
    writer: &mut impl Write,
    process_cancellation: &BrokerProcessRunCancellation,
    clocks: &mut ConnectionClocks<M, T>,
) -> Result<(BrokerConnectionClass, BrokerConnectionExit), BrokerConnectionRouteError>
where
    S: ControllerKeyStore,
    M: FnMut() -> Instant,
    T: FnMut() -> Result<StateTimestamp, BrokerConnectionRouteError>,
{
    let first_payload = read_initial_frame(reader)?;
    match classify_first_frame(&first_payload)? {
        BrokerConnectionClass::Consumer => {
            let mut replay = FirstFrameReader::new(first_payload, reader);
            runtime
                .process()
                .serve_runtime_connection_with_process_cancellation(
                    runtime,
                    observed_identity,
                    &mut replay,
                    writer,
                    process_cancellation,
                )
                .map(|exit| (BrokerConnectionClass::Consumer, exit))
                .map_err(BrokerConnectionRouteError::Consumer)
        }
        BrokerConnectionClass::HumanControl => serve_human_control_connection(
            runtime,
            dispatcher,
            first_payload,
            reader,
            writer,
            &mut clocks.monotonic_now,
            &mut clocks.state_now,
        )
        .map(|exit| (BrokerConnectionClass::HumanControl, exit)),
    }
}

fn serve_human_control_connection<S>(
    runtime: &mut BrokerRuntime,
    dispatcher: &HumanControlDispatcher<S>,
    first_payload: Zeroizing<Vec<u8>>,
    reader: &mut impl Read,
    writer: &mut impl Write,
    monotonic_now: &mut impl FnMut() -> Instant,
    state_now: &mut impl FnMut() -> Result<StateTimestamp, BrokerConnectionRouteError>,
) -> Result<BrokerConnectionExit, BrokerConnectionRouteError>
where
    S: ControllerKeyStore,
{
    let mut state = ClosingHumanControlState(dispatcher.connection());
    let first = decode_human_control_hello_wire_envelope(HumanControlFrame::from(
        first_payload.as_slice().to_vec(),
    ))
    .map_err(BrokerConnectionRouteError::HumanControl)?;
    if first.operation() != HumanControlOperation::Hello {
        state.close();
        return Err(BrokerConnectionRouteError::UnknownProtocol);
    }
    let mut next = Some(first);

    loop {
        let envelope = match next.take() {
            Some(envelope) => envelope,
            None => match read_human_control_frame(reader) {
                Ok(Some(frame)) => {
                    let selected = selected_protocol(state.phase())
                        .ok_or(BrokerConnectionRouteError::UnknownProtocol)?;
                    decode_human_control_wire_envelope(frame, selected)
                        .map_err(BrokerConnectionRouteError::HumanControl)?
                }
                Ok(None) => {
                    state.close();
                    return Ok(BrokerConnectionExit::PeerClosed);
                }
                Err(error) => {
                    state.close();
                    return Err(BrokerConnectionRouteError::HumanControl(error));
                }
            },
        };

        let request_id = envelope.request_id();
        let version = envelope.version();
        let operation = envelope.operation();
        let observed_at = state_now()?;
        let typed = match envelope.to_typed_request(observed_at) {
            Ok(request) => request,
            Err(_) => {
                let failure = HumanControlProtocolFailure::new(
                    HumanControlFailureCode::InvalidRequest,
                    false,
                    None,
                );
                let payload = encode_human_control_failure(request_id, version, failure)
                    .map_err(BrokerConnectionRouteError::HumanControl)?;
                write_human_control_frame(writer, &payload)
                    .map_err(BrokerConnectionRouteError::HumanControl)?;
                state.close();
                return Ok(BrokerConnectionExit::ClosedByBroker);
            }
        };

        match dispatcher.dispatch(runtime, &mut state, typed, monotonic_now(), observed_at) {
            Ok(response) => {
                let response_version = selected_protocol(state.phase()).unwrap_or(version);
                let payload = encode_human_control_response(
                    request_id,
                    response_version,
                    operation,
                    &response,
                )
                .map_err(BrokerConnectionRouteError::HumanControl)?;
                write_human_control_frame(writer, &payload)
                    .map_err(BrokerConnectionRouteError::HumanControl)?;
            }
            Err(error) => {
                let failure = error.failure();
                let payload = encode_human_control_failure(request_id, version, failure)
                    .map_err(BrokerConnectionRouteError::HumanControl)?;
                write_human_control_frame(writer, &payload)
                    .map_err(BrokerConnectionRouteError::HumanControl)?;
                if state.phase() == HumanControlConnectionPhase::Closed {
                    return Ok(BrokerConnectionExit::ClosedByBroker);
                }
            }
        }

        if state.phase() == HumanControlConnectionPhase::Closed {
            return Ok(BrokerConnectionExit::ClosedByBroker);
        }
    }
}

fn selected_protocol(phase: HumanControlConnectionPhase) -> Option<HumanControlProtocolVersion> {
    match phase {
        HumanControlConnectionPhase::Negotiated(version)
        | HumanControlConnectionPhase::Authenticated {
            protocol: version, ..
        } => Some(version),
        HumanControlConnectionPhase::AwaitingHello | HumanControlConnectionPhase::Closed => None,
    }
}

fn read_initial_frame(
    reader: &mut impl Read,
) -> Result<Zeroizing<Vec<u8>>, BrokerConnectionRouteError> {
    let mut header = [0_u8; 4];
    read_exact(reader, &mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_BROKER_HELLO_LENGTH {
        return Err(BrokerConnectionRouteError::InitialFrame);
    }
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    read_exact(reader, payload.as_mut_slice())?;
    Ok(payload)
}

fn read_exact(reader: &mut impl Read, buffer: &mut [u8]) -> Result<(), BrokerConnectionRouteError> {
    let mut offset = 0;
    while offset < buffer.len() {
        match reader.read(&mut buffer[offset..]) {
            Ok(0) => return Err(BrokerConnectionRouteError::InitialFrame),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(BrokerConnectionRouteError::InitialFrame),
        }
    }
    Ok(())
}

fn classify_first_frame(
    payload: &[u8],
) -> Result<BrokerConnectionClass, BrokerConnectionRouteError> {
    let value = crate::protocol::parse_unique_json(payload)
        .map_err(|_| BrokerConnectionRouteError::UnknownProtocol)?;
    let Value::Object(envelope) = value else {
        return Err(BrokerConnectionRouteError::UnknownProtocol);
    };
    let consumer = matches!(
        envelope.get("protocol_name"),
        Some(Value::String(value)) if value == BROKER_PROTOCOL_NAME
    );
    let human_control = matches!(
        envelope.get("protocol"),
        Some(Value::String(value)) if value == HUMAN_CONTROL_PROTOCOL_NAME
    );
    match (consumer, human_control) {
        (true, false) => Ok(BrokerConnectionClass::Consumer),
        (false, true) => Ok(BrokerConnectionClass::HumanControl),
        _ => Err(BrokerConnectionRouteError::UnknownProtocol),
    }
}

fn current_state_timestamp() -> Result<StateTimestamp, BrokerConnectionRouteError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BrokerConnectionRouteError::ClockUnavailable)?;
    let millis = i64::try_from(elapsed.as_millis())
        .map_err(|_| BrokerConnectionRouteError::ClockUnavailable)?;
    StateTimestamp::from_unix_millis(millis)
        .map_err(|_| BrokerConnectionRouteError::ClockUnavailable)
}

struct FirstFrameReader<'a, R> {
    first: Cursor<Zeroizing<Vec<u8>>>,
    reader: &'a mut R,
}

struct ConnectionClocks<M, T> {
    monotonic_now: M,
    state_now: T,
}

struct ClosingHumanControlState(crate::HumanControlConnectionState);

impl Deref for ClosingHumanControlState {
    type Target = crate::HumanControlConnectionState;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ClosingHumanControlState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ClosingHumanControlState {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl<'a, R> FirstFrameReader<'a, R> {
    fn new(payload: Zeroizing<Vec<u8>>, reader: &'a mut R) -> Self {
        let mut first = Zeroizing::new(Vec::with_capacity(payload.len() + 4));
        first.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        first.extend_from_slice(&payload);
        Self {
            first: Cursor::new(first),
            reader,
        }
    }
}

impl<R> Read for FirstFrameReader<'_, R>
where
    R: Read,
{
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.first.read(buffer)?;
        if read != 0 {
            return Ok(read);
        }
        self.reader.read(buffer)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, SystemTime};

    use psw_core::{SecretBytes, VaultId};

    use super::*;
    use crate::{
        decode_human_control_response, encode_broker_request, encode_human_control_request,
        read_broker_frame, write_broker_frame, write_human_control_frame, BrokerHelloRequest,
        BrokerProtocolVersion, BrokerProtocolVersionRange, BrokerRequest, BrokerRequestEnvelope,
        BrokerRequestId, ControllerChallengeRequest, ControllerKeyStoreError, ControllerNonce,
        ControllerSigningKey, DeviceKeyStore, DeviceKeyStoreError, DevicePaths, DeviceRootKey,
        HumanControlClientResponse, HumanControlProtocolVersionRange, HumanControlRequest,
        HumanControlRequestId, HumanControlVaultUnlockCredential, HumanControlVersionOffer,
        CONTROLLER_ROLE, HUMAN_CONTROL_SCHEMA_ID,
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Default)]
    struct MemoryDeviceKeyStore {
        bytes: Arc<Mutex<Option<Vec<u8>>>>,
    }

    impl DeviceKeyStore for MemoryDeviceKeyStore {
        fn load(&self) -> Result<Option<DeviceRootKey>, DeviceKeyStoreError> {
            self.bytes
                .lock()
                .expect("device key lock")
                .as_ref()
                .map(|bytes| DeviceRootKey::from_stored_bytes(bytes.clone()))
                .transpose()
        }

        fn create_new(&self, key: &DeviceRootKey) -> Result<(), DeviceKeyStoreError> {
            let mut bytes = self.bytes.lock().expect("device key lock");
            if bytes.is_some() {
                return Err(DeviceKeyStoreError::AlreadyExists);
            }
            *bytes = Some(key.expose().to_vec());
            Ok(())
        }

        fn delete(&self) -> Result<bool, DeviceKeyStoreError> {
            Ok(self.bytes.lock().expect("device key lock").take().is_some())
        }
    }

    #[derive(Clone)]
    struct MemoryControllerKeyStore {
        seed: Arc<Mutex<Option<Vec<u8>>>>,
        removal_marker: Arc<Mutex<bool>>,
    }

    impl MemoryControllerKeyStore {
        fn seeded(byte: u8) -> Self {
            Self {
                seed: Arc::new(Mutex::new(Some(vec![byte; 32]))),
                removal_marker: Arc::new(Mutex::new(false)),
            }
        }
    }

    impl ControllerKeyStore for MemoryControllerKeyStore {
        fn load_seed(&self) -> Result<Option<ControllerSigningKey>, ControllerKeyStoreError> {
            self.seed
                .lock()
                .expect("controller key lock")
                .as_ref()
                .map(|seed| ControllerSigningKey::from_stored_bytes(seed.clone()))
                .transpose()
        }

        fn create_seed(&self, key: &ControllerSigningKey) -> Result<(), ControllerKeyStoreError> {
            let mut seed = self.seed.lock().expect("controller key lock");
            if seed.is_some() {
                return Err(ControllerKeyStoreError::AlreadyExists);
            }
            *seed = Some(key.expose_seed().to_vec());
            Ok(())
        }

        fn delete_seed(&self) -> Result<bool, ControllerKeyStoreError> {
            Ok(self
                .seed
                .lock()
                .expect("controller key lock")
                .take()
                .is_some())
        }

        fn removal_pending(&self) -> Result<bool, ControllerKeyStoreError> {
            Ok(*self.removal_marker.lock().expect("controller marker lock"))
        }

        fn create_removal_marker(&self) -> Result<(), ControllerKeyStoreError> {
            let mut marker = self.removal_marker.lock().expect("controller marker lock");
            if *marker {
                return Err(ControllerKeyStoreError::AlreadyExists);
            }
            *marker = true;
            Ok(())
        }

        fn delete_removal_marker(&self) -> Result<bool, ControllerKeyStoreError> {
            let mut marker = self.removal_marker.lock().expect("controller marker lock");
            Ok(std::mem::replace(&mut *marker, false))
        }
    }

    struct TestHome {
        path: std::path::PathBuf,
        paths: DevicePaths,
    }

    impl TestHome {
        fn new(label: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "keptnear-human-connection-{label}-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test home");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("home mode");
            let paths = DevicePaths::prepare_for_test_home(&path).expect("device paths");
            Self { path, paths }
        }
    }

    impl Drop for TestHome {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn timestamp(value: i64) -> StateTimestamp {
        StateTimestamp::from_unix_millis(value).expect("timestamp")
    }

    fn runtime(home: &TestHome) -> BrokerRuntime {
        BrokerRuntime::open_or_initialize_with_paths_at(
            home.paths.clone(),
            MemoryDeviceKeyStore::default(),
            timestamp(100),
        )
        .expect("runtime")
    }

    fn hello(version_major: u16) -> HumanControlRequest {
        HumanControlRequest::Hello(
            HumanControlVersionOffer::new(
                CONTROLLER_ROLE,
                [HumanControlProtocolVersionRange::new(version_major, 0, 0).expect("range")],
                [HUMAN_CONTROL_SCHEMA_ID.to_owned()],
            )
            .expect("offer"),
        )
    }

    fn framed_human_request(
        request_id: HumanControlRequestId,
        request: &HumanControlRequest,
    ) -> Vec<u8> {
        let payload = encode_human_control_request(
            request_id,
            HumanControlProtocolVersion::current(),
            request,
        )
        .expect("encode request");
        let mut frame = Vec::new();
        write_human_control_frame(&mut frame, payload.as_bytes()).expect("write request frame");
        frame
    }

    fn exchange(
        stream: &mut UnixStream,
        request: &HumanControlRequest,
    ) -> (HumanControlClientResponse, Vec<u8>) {
        let request_id = HumanControlRequestId::generate();
        stream
            .write_all(&framed_human_request(request_id, request))
            .expect("write request");
        let response = read_human_control_frame(stream)
            .expect("read response")
            .expect("response frame");
        let raw = response.as_bytes().to_vec();
        let decoded = decode_human_control_response(
            response.as_bytes(),
            request_id,
            HumanControlProtocolVersion::current(),
            request.operation(),
        )
        .expect("decode response");
        (decoded, raw)
    }

    #[test]
    fn first_frame_classifier_selects_one_exact_protocol_and_rejects_ambiguity() {
        let consumer = BrokerRequestEnvelope::new(
            BrokerProtocolVersion::current(),
            BrokerRequestId::generate(),
            BrokerRequest::Hello(
                BrokerHelloRequest::new(
                    vec![BrokerProtocolVersionRange::new(1, 0, 0).expect("range")],
                    vec![],
                )
                .expect("hello"),
            ),
        );
        let consumer_payload = encode_broker_request(&consumer).expect("consumer request");
        assert_eq!(
            classify_first_frame(&consumer_payload),
            Ok(BrokerConnectionClass::Consumer)
        );

        let human = encode_human_control_request(
            HumanControlRequestId::generate(),
            HumanControlProtocolVersion::current(),
            &hello(1),
        )
        .expect("human request");
        assert_eq!(
            classify_first_frame(human.as_bytes()),
            Ok(BrokerConnectionClass::HumanControl)
        );

        let malformed = [
            format!(
                r#"{{"protocol":"{HUMAN_CONTROL_PROTOCOL_NAME}","protocol":"{HUMAN_CONTROL_PROTOCOL_NAME}"}}"#
            ),
            format!(
                r#"{{"protocol":"{HUMAN_CONTROL_PROTOCOL_NAME}","protocol_name":"{BROKER_PROTOCOL_NAME}"}}"#
            ),
            r#"{"protocol":"future"}"#.to_owned(),
            r#"{"operation":"hello"}"#.to_owned(),
        ];
        for malformed in malformed {
            assert_eq!(
                classify_first_frame(malformed.as_bytes()),
                Err(BrokerConnectionRouteError::UnknownProtocol)
            );
        }

        let mut oversized = Cursor::new(
            ((MAX_BROKER_HELLO_LENGTH + 1) as u32)
                .to_be_bytes()
                .to_vec(),
        );
        assert_eq!(
            read_initial_frame(&mut oversized),
            Err(BrokerConnectionRouteError::InitialFrame)
        );
    }

    #[test]
    fn incompatible_human_hello_returns_one_fixed_failure_and_closes() {
        let home = TestHome::new("incompatible");
        let mut runtime = runtime(&home);
        let dispatcher = HumanControlDispatcher::new(
            runtime.process().broker_instance_id(),
            MemoryControllerKeyStore::seeded(0x41),
        );
        let request = hello(2);
        let request_id = HumanControlRequestId::generate();
        let mut reader = Cursor::new(framed_human_request(request_id, &request));
        let mut writer = Vec::new();
        let base = Instant::now();
        let mut clocks = ConnectionClocks {
            monotonic_now: || base,
            state_now: || Ok(timestamp(101)),
        };
        let result = serve_routed_broker_connection_with_clocks(
            &mut runtime,
            &dispatcher,
            &ObservedConsumerIdentity::default(),
            &mut reader,
            &mut writer,
            &BrokerProcessRunCancellation::default(),
            &mut clocks,
        )
        .expect("fixed failure");
        assert_eq!(
            result,
            (
                BrokerConnectionClass::HumanControl,
                BrokerConnectionExit::ClosedByBroker
            )
        );
        let frame = read_human_control_frame(&mut Cursor::new(&writer))
            .expect("response")
            .expect("response frame");
        let HumanControlClientResponse::Failure(failure) = decode_human_control_response(
            frame.as_bytes(),
            request_id,
            HumanControlProtocolVersion::current(),
            HumanControlOperation::Hello,
        )
        .expect("fixed response") else {
            panic!("expected failure");
        };
        assert_eq!(
            failure.code(),
            HumanControlFailureCode::ProtocolIncompatible
        );
        assert_eq!(writer.len(), frame.as_bytes().len() + 4);
        runtime.shutdown_at(timestamp(102)).expect("shutdown");
    }

    #[test]
    fn routed_connection_replays_the_consumer_first_frame_unchanged() {
        let home = TestHome::new("consumer-route");
        let mut runtime = runtime(&home);
        let dispatcher = HumanControlDispatcher::new(
            runtime.process().broker_instance_id(),
            MemoryControllerKeyStore::seeded(0x49),
        );
        let request = BrokerRequestEnvelope::new(
            BrokerProtocolVersion::current(),
            BrokerRequestId::generate(),
            BrokerRequest::Hello(
                BrokerHelloRequest::new(
                    vec![BrokerProtocolVersionRange::new(1, 0, 0).expect("range")],
                    vec![],
                )
                .expect("hello"),
            ),
        );
        let payload = encode_broker_request(&request).expect("consumer request");
        let mut input = Vec::new();
        write_broker_frame(&mut input, &payload).expect("consumer frame");
        let mut reader = Cursor::new(input);
        let mut writer = Vec::new();
        let base = Instant::now();
        let mut clocks = ConnectionClocks {
            monotonic_now: || base,
            state_now: || Ok(timestamp(103)),
        };
        assert_eq!(
            serve_routed_broker_connection_with_clocks(
                &mut runtime,
                &dispatcher,
                &ObservedConsumerIdentity::default(),
                &mut reader,
                &mut writer,
                &BrokerProcessRunCancellation::default(),
                &mut clocks,
            )
            .expect("consumer route"),
            (
                BrokerConnectionClass::Consumer,
                BrokerConnectionExit::PeerClosed
            )
        );
        let response = read_broker_frame(&mut Cursor::new(&writer))
            .expect("consumer response")
            .expect("consumer response frame");
        let response = crate::decode_broker_response(&response).expect("decode response");
        assert_eq!(response.request_id(), request.request_id());
        assert!(matches!(
            response.response(),
            crate::BrokerResponse::Hello(_)
        ));
        runtime.shutdown_at(timestamp(104)).expect("shutdown");
    }

    #[test]
    fn routed_connection_authenticates_dispatches_and_drops_private_markers() {
        let home = TestHome::new("authenticated");
        let mut runtime = runtime(&home);
        let broker_instance_id = runtime.process().broker_instance_id();
        let dispatcher =
            HumanControlDispatcher::new(broker_instance_id, MemoryControllerKeyStore::seeded(0x51));
        let signing_key =
            ControllerSigningKey::from_stored_bytes(vec![0x51; 32]).expect("controller key");
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("write timeout");

        let server_thread = thread::spawn(move || {
            let mut reader = server.try_clone().expect("clone server");
            let base = Instant::now();
            let mut observed_at = 200_i64;
            let mut clocks = ConnectionClocks {
                monotonic_now: || base,
                state_now: || {
                    observed_at += 1;
                    Ok(timestamp(observed_at))
                },
            };
            let result = serve_routed_broker_connection_with_clocks(
                &mut runtime,
                &dispatcher,
                &ObservedConsumerIdentity::default(),
                &mut reader,
                &mut server,
                &BrokerProcessRunCancellation::default(),
                &mut clocks,
            );
            runtime.shutdown_at(timestamp(299)).expect("shutdown");
            result
        });

        let (HumanControlClientResponse::Success(hello_response), _) =
            exchange(&mut client, &hello(1))
        else {
            panic!("hello success");
        };
        let (protocol, schema, selected_instance) =
            hello_response.hello_selection().expect("hello selection");
        assert_eq!(protocol, HumanControlProtocolVersion::current());
        assert_eq!(schema, HUMAN_CONTROL_SCHEMA_ID);
        assert_eq!(selected_instance, broker_instance_id);
        assert!(hello_response.has_complete_operation_catalog());

        let challenge_request =
            HumanControlRequest::ControllerChallenge(ControllerChallengeRequest::new(
                signing_key.controller_id(),
                ControllerNonce::from_bytes([0x52; 32]),
            ));
        let (HumanControlClientResponse::Success(challenge_response), _) =
            exchange(&mut client, &challenge_request)
        else {
            panic!("challenge success");
        };
        let challenge = challenge_response
            .controller_challenge()
            .expect("controller challenge");
        assert_eq!(challenge.public_key(), signing_key.public_key());

        let authenticate =
            HumanControlRequest::ControllerAuthenticate(challenge.prove(&signing_key));
        let (HumanControlClientResponse::Success(authenticated), _) =
            exchange(&mut client, &authenticate)
        else {
            panic!("authentication success");
        };
        let (controller_id, _, lease_duration_millis) = authenticated
            .authenticated_session()
            .expect("authenticated session");
        assert_eq!(controller_id, signing_key.controller_id());
        assert_eq!(lease_duration_millis, 30_000);

        let (HumanControlClientResponse::Success(readiness), _) =
            exchange(&mut client, &HumanControlRequest::ReadinessGet)
        else {
            panic!("readiness success");
        };
        assert_eq!(readiness.operation(), HumanControlOperation::ReadinessGet);
        assert_eq!(
            readiness
                .result()
                .get("humanControlSchema")
                .and_then(Value::as_str),
            Some(HUMAN_CONTROL_SCHEMA_ID)
        );

        let secret_marker = "KN_HUMAN_CONTROL_PRIVATE_MARKER_51";
        let unlock = HumanControlRequest::VaultUnlock {
            vault_id: VaultId::generate(),
            credential: HumanControlVaultUnlockCredential::MasterPassword(SecretBytes::new(
                secret_marker.as_bytes().to_vec(),
            )),
        };
        let (HumanControlClientResponse::Failure(failure), raw_failure) =
            exchange(&mut client, &unlock)
        else {
            panic!("unlock failure");
        };
        assert_eq!(failure.code(), HumanControlFailureCode::UnlockFailed);
        assert!(!raw_failure
            .windows(secret_marker.len())
            .any(|window| window == secret_marker.as_bytes()));
        assert!(!format!("{failure:?}").contains(secret_marker));

        client
            .shutdown(std::net::Shutdown::Write)
            .expect("close requests");
        assert_eq!(
            server_thread.join().expect("server thread").expect("serve"),
            (
                BrokerConnectionClass::HumanControl,
                BrokerConnectionExit::PeerClosed
            )
        );
    }
}
