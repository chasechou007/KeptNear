use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use psw_core::{
    CreateVaultRequest, CredentialDraft, CredentialField, CredentialId, ExportItemsRequest,
    LoginItem, OpenVaultRequest, SecretBytes, SecretFieldId, SecretFieldKind, UnlockRequest,
    VaultCore, VaultId, VaultItemContent, VaultItemDraft,
};

use crate::access_rule::{BrokerAccessRuleApproval, BrokerAccessRuleEvaluation};
use crate::approval::{BrokerApprovalDecision, BrokerApprovalError};
use crate::audit::{BrokerAuditClearConfirmation, BrokerAuditFilter};
use crate::capability_protocol::{
    BrokerAccessRequest, BrokerAccessResponse, BrokerGrantStatusRequest,
};
use crate::controller_authentication::ControllerChallengeRequest;
use crate::controller_authority_contract::CONTROLLER_ROLE;
use crate::controller_key::{ControllerKeyStore, ControllerKeyStoreError, ControllerSigningKey};
use crate::credential_matching::{
    BrokerCredentialCandidateSelection, BrokerCredentialMatchingError, BrokerNewCredentialRequest,
};
use crate::credential_search::BrokerCredentialSearchQuery;
use crate::device_key::{
    DeviceKeyError, DeviceKeyManager, DeviceKeyStore, DeviceKeyStoreError, DeviceRootKey,
};
use crate::http_request::{
    BrokerHttpCredentialHeader, BrokerHttpHeader, BrokerHttpMethod, BrokerHttpRequest,
    BrokerHttpRequestError, BrokerHttpTransport, BrokerHttpTransportResponse,
};
use crate::human_control::{BrokerPendingRequestId, BrokerPendingRequestKind};
use crate::human_control_dispatcher::{HumanControlDispatcher, HumanControlRequest};
use crate::human_control_protocol::{
    HumanControlProtocolVersion, HumanControlProtocolVersionRange, HumanControlVersionOffer,
    HUMAN_CONTROL_SCHEMA_ID,
};
use crate::human_control_types::{ControllerNonce, HumanControlRequestId};
use crate::local_data::BrokerLocalDataError;
use crate::machine_access::BrokerMachineAccessError;
use crate::outbound_operation::{BrokerOutboundOperationError, BrokerOutboundOperationOutcome};
use crate::pairing::{
    BrokerPairingAuthorizationEffect, BrokerPairingError, BrokerPairingRequestStatus,
    BrokerPairingUserApproval, ConsumerPairingProposal,
};
use crate::paths::DevicePaths;
use crate::process::BrokerProcess;
use crate::process_run::{
    BrokerProcessEnvironment, BrokerProcessRunCancellation, BrokerProcessRunError,
    BrokerProcessRunRequest,
};
use crate::protocol::{
    decode_broker_response, encode_broker_request, BrokerAuthenticationCompleteRequest,
    BrokerAuthenticationStartRequest, BrokerCapabilityVersions, BrokerErrorCode,
    BrokerHelloRequest, BrokerPairingCompleteRequest, BrokerPairingProgressResponse,
    BrokerPairingStartRequest, BrokerPairingStatusRequest, BrokerProtocolVersion,
    BrokerProtocolVersionRange, BrokerRequest, BrokerRequestEnvelope, BrokerRequestId,
    BrokerResponse,
};
use crate::revocation::BrokerRevocationKind;
use crate::runtime::{BrokerRuntime, BrokerRuntimeError};
use crate::state_model::{
    AccessRule, ApprovalStatus, ApprovalSubject, AuditDecision, AuditEvent, AuditEventKind,
    AuditScope, AuthorizationTarget, Capability, CapabilityName, ConfirmationMethod,
    ConfirmationPolicy, Consumer, CredentialFieldScope, GrantScope, ObservedConsumerIdentity,
    RuleLifetime, StateTimestamp, UsagePlacement, UsageProfile, UsageProfileDefinition, UseGrant,
    UseGrantId, VaultSessionId,
};
use crate::state_store::{
    DeviceStateError, DeviceStateFileEntry, DeviceStateStore, DEVICE_STATE_DATABASE_FILENAME,
};
use crate::usage_profile::BrokerUsageProfileError;
use crate::use_grant::{BrokerAllowOnceApproval, BrokerUseGrantBasis, BrokerUseGrantError};
use crate::{
    decode_human_control_response, encode_human_control_request, read_human_control_frame,
    write_human_control_frame, BrokerConnectionClass, BrokerConnectionExit,
    HumanControlClientResponse, UnixBrokerConnection, UnixBrokerListener, UnixBrokerTransportEntry,
    UnixBrokerTransportError, UnixBrokerTransportOperation,
};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct MemoryKeyState {
    bytes: Option<Vec<u8>>,
    load_error: Option<DeviceKeyStoreError>,
}

#[derive(Clone, Default)]
struct MemoryKeyStore {
    state: Arc<Mutex<MemoryKeyState>>,
}

impl MemoryKeyStore {
    fn bytes(&self) -> Option<Vec<u8>> {
        self.state.lock().expect("key state").bytes.clone()
    }

    fn forget(&self) {
        self.state.lock().expect("key state").bytes.take();
    }

    fn replace(&self, bytes: Vec<u8>) {
        self.state.lock().expect("key state").bytes = Some(bytes);
    }
}

impl DeviceKeyStore for MemoryKeyStore {
    fn load(&self) -> Result<Option<DeviceRootKey>, DeviceKeyStoreError> {
        let mut state = self.state.lock().expect("key state");
        if let Some(error) = state.load_error.take() {
            return Err(error);
        }
        state
            .bytes
            .clone()
            .map(DeviceRootKey::from_stored_bytes)
            .transpose()
    }

    fn create_new(&self, key: &DeviceRootKey) -> Result<(), DeviceKeyStoreError> {
        let mut state = self.state.lock().expect("key state");
        if state.bytes.is_some() {
            return Err(DeviceKeyStoreError::AlreadyExists);
        }
        state.bytes = Some(key.expose().to_vec());
        Ok(())
    }

    fn delete(&self) -> Result<bool, DeviceKeyStoreError> {
        Ok(self.state.lock().expect("key state").bytes.take().is_some())
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
            .expect("controller key")
            .as_ref()
            .map(|seed| ControllerSigningKey::from_stored_bytes(seed.clone()))
            .transpose()
    }

    fn create_seed(&self, key: &ControllerSigningKey) -> Result<(), ControllerKeyStoreError> {
        let mut seed = self.seed.lock().expect("controller key");
        if seed.is_some() {
            return Err(ControllerKeyStoreError::AlreadyExists);
        }
        *seed = Some(key.expose_seed().to_vec());
        Ok(())
    }

    fn delete_seed(&self) -> Result<bool, ControllerKeyStoreError> {
        Ok(self.seed.lock().expect("controller key").take().is_some())
    }

    fn removal_pending(&self) -> Result<bool, ControllerKeyStoreError> {
        Ok(*self.removal_marker.lock().expect("controller marker"))
    }

    fn create_removal_marker(&self) -> Result<(), ControllerKeyStoreError> {
        let mut marker = self.removal_marker.lock().expect("controller marker");
        if *marker {
            return Err(ControllerKeyStoreError::AlreadyExists);
        }
        *marker = true;
        Ok(())
    }

    fn delete_removal_marker(&self) -> Result<bool, ControllerKeyStoreError> {
        let mut marker = self.removal_marker.lock().expect("controller marker");
        Ok(std::mem::replace(&mut *marker, false))
    }
}

struct TestHome {
    path: PathBuf,
    paths: DevicePaths,
}

impl TestHome {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "keptnear-broker-integration-{label}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test home");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("protect test home");
        let paths = DevicePaths::prepare_for_test_home(&path).expect("prepare device paths");
        Self { path, paths }
    }

    fn new_short(label: &str) -> Self {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path =
            PathBuf::from("/tmp").join(format!("kn-{label}-{}-{sequence}", std::process::id()));
        fs::create_dir(&path).expect("create short test home");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("protect short test home");
        let paths = DevicePaths::prepare_for_test_home(&path).expect("prepare device paths");
        Self { path, paths }
    }

    fn database_path(&self) -> PathBuf {
        self.paths.state().join(DEVICE_STATE_DATABASE_FILENAME)
    }

    fn create_vault(&self, label: &str) -> TestVault {
        let path = self.path.join(format!("{label}.pswvault"));
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let locked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: path.clone(),
                display_name: Some("Broker restart fixture".to_owned()),
                master_password: password.clone(),
            })
            .expect("create current vault");
        TestVault {
            path,
            vault_id: locked.metadata.vault_id.expect("stable vault ID"),
            password,
        }
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct TestVault {
    path: PathBuf,
    vault_id: VaultId,
    password: SecretBytes,
}

struct ExpectedHttpTransport {
    expected_method: BrokerHttpMethod,
    expected_url: String,
    expected_header_name: String,
    expected_header_value: String,
    expected_body: Vec<u8>,
    response: Mutex<Option<Result<BrokerHttpTransportResponse, BrokerHttpRequestError>>>,
}

impl ExpectedHttpTransport {
    fn succeeding(
        expected_url: &str,
        expected_header_name: &str,
        expected_header_value: &str,
        expected_body: &[u8],
        response_body: Vec<u8>,
    ) -> Self {
        Self {
            expected_method: BrokerHttpMethod::Post,
            expected_url: expected_url.to_owned(),
            expected_header_name: expected_header_name.to_owned(),
            expected_header_value: expected_header_value.to_owned(),
            expected_body: expected_body.to_vec(),
            response: Mutex::new(Some(Ok(BrokerHttpTransportResponse::new(
                201,
                response_body,
                false,
            )))),
        }
    }

    fn failing(
        expected_url: &str,
        expected_header_name: &str,
        expected_header_value: &str,
        expected_body: &[u8],
    ) -> Self {
        Self {
            expected_method: BrokerHttpMethod::Post,
            expected_url: expected_url.to_owned(),
            expected_header_name: expected_header_name.to_owned(),
            expected_header_value: expected_header_value.to_owned(),
            expected_body: expected_body.to_vec(),
            response: Mutex::new(Some(Err(BrokerHttpRequestError::NetworkOperationFailed))),
        }
    }
}

impl BrokerHttpTransport for ExpectedHttpTransport {
    fn send(
        &self,
        request: &BrokerHttpRequest,
        credential_header: &BrokerHttpCredentialHeader,
        _response_capture_limit: usize,
    ) -> Result<BrokerHttpTransportResponse, BrokerHttpRequestError> {
        assert_eq!(request.method(), self.expected_method);
        assert_eq!(request.url(), self.expected_url);
        assert_eq!(request.body(), self.expected_body);
        assert_eq!(credential_header.name(), self.expected_header_name);
        assert_eq!(credential_header.value(), self.expected_header_value);
        self.response
            .lock()
            .expect("HTTP response")
            .take()
            .expect("one HTTP call")
    }
}

fn timestamp(value: i64) -> StateTimestamp {
    StateTimestamp::from_unix_millis(value).expect("timestamp")
}

fn initialize_state(home: &TestHome, key_store: &MemoryKeyStore) -> DeviceStateStore {
    let root_key = DeviceKeyManager::new(key_store.clone())
        .initialize_new()
        .expect("initialize device key");
    DeviceStateStore::initialize_new(&home.paths, &root_key, timestamp(100))
        .expect("initialize encrypted state")
}

fn human_control_hello() -> HumanControlRequest {
    HumanControlRequest::Hello(
        HumanControlVersionOffer::new(
            CONTROLLER_ROLE,
            [HumanControlProtocolVersionRange::new(1, 0, 0).expect("range")],
            [HUMAN_CONTROL_SCHEMA_ID.to_owned()],
        )
        .expect("offer"),
    )
}

fn exchange_human_control(
    connection: &mut UnixBrokerConnection,
    request: &HumanControlRequest,
) -> HumanControlClientResponse {
    let request_id = HumanControlRequestId::generate();
    let payload =
        encode_human_control_request(request_id, HumanControlProtocolVersion::current(), request)
            .expect("encode request");
    write_human_control_frame(connection, payload.as_bytes()).expect("write request");
    let response = read_human_control_frame(connection)
        .expect("read response")
        .expect("response frame");
    decode_human_control_response(
        response.as_bytes(),
        request_id,
        HumanControlProtocolVersion::current(),
        request.operation(),
    )
    .expect("decode response")
}

fn seed_authorization(
    state: &DeviceStateStore,
    vault_id: VaultId,
    vault_session_id: VaultSessionId,
) -> (Consumer, AccessRule, UseGrant) {
    let consumer = Consumer::new(
        [0x41; 32],
        "Restart integration Consumer".to_owned(),
        ObservedConsumerIdentity::new(
            Some("integration-adapter".to_owned()),
            Some("app.keptnear.integration".to_owned()),
            None,
            Some([0x42; 32]),
        )
        .expect("observed identity"),
        timestamp(110),
    )
    .expect("consumer");
    state.insert_consumer(&consumer).expect("insert consumer");
    let target = AuthorizationTarget::new(
        consumer.consumer_id(),
        CredentialFieldScope::new(
            vault_id,
            CredentialId::generate(),
            SecretFieldId::generate(),
        ),
        Capability::v1(CapabilityName::ProcessRun),
    );
    let rule = AccessRule::new(
        target,
        ConfirmationPolicy::OncePerUnlockSession,
        RuleLifetime::Persistent,
        timestamp(120),
    )
    .expect("access rule");
    state.insert_access_rule(&rule).expect("insert rule");
    let grant = UseGrant::new(
        target,
        Some(rule.access_rule_id()),
        vault_session_id,
        GrantScope::UnlockSession,
        timestamp(130),
        timestamp(500),
    )
    .expect("use grant");
    state.insert_use_grant(&grant).expect("insert grant");
    (consumer, rule, grant)
}

fn assert_path_free(error: &BrokerRuntimeError, home: &Path) {
    let rendered = error.to_string();
    assert!(!rendered.contains(home.to_string_lossy().as_ref()));
    assert!(!rendered.contains("correct horse"));
    assert!(!rendered.contains("Restart integration Consumer"));
}

fn read_directory_tree_bytes(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in fs::read_dir(path).expect("read directory tree") {
        let entry = entry.expect("directory tree entry");
        if entry
            .file_type()
            .expect("directory tree entry type")
            .is_dir()
        {
            bytes.extend(read_directory_tree_bytes(&entry.path()));
        } else {
            bytes.extend(fs::read(entry.path()).expect("read directory tree file"));
        }
    }
    bytes
}

#[test]
fn first_run_initializes_only_when_device_key_and_managed_state_are_both_absent() {
    let home = TestHome::new("first-run");
    let key_store = MemoryKeyStore::default();

    let mut runtime = BrokerRuntime::open_or_initialize_with_paths_at(
        home.paths.clone(),
        key_store.clone(),
        timestamp(100),
    )
    .expect("initialize first run");

    assert!(key_store.bytes().is_some());
    assert!(home.database_path().is_file());
    assert_eq!(runtime.stale_use_grants_removed(), 0);
    runtime.shutdown_at(timestamp(110)).expect("shutdown");
    drop(runtime);

    let mut reopened = BrokerRuntime::open_or_initialize_with_paths_at(
        home.paths.clone(),
        key_store.clone(),
        timestamp(120),
    )
    .expect("reopen initialized state");
    assert_eq!(reopened.stale_use_grants_removed(), 0);
    reopened.shutdown_at(timestamp(130)).expect("shutdown");
}

#[test]
fn human_approval_actions_preserve_exact_vault_and_capability_bindings() {
    let home = TestHome::new("human-approval-bindings");
    let key_store = MemoryKeyStore::default();
    let mut runtime = BrokerRuntime::open_or_initialize_with_paths_at(
        home.paths.clone(),
        key_store,
        timestamp(100),
    )
    .expect("runtime");
    let consumer = Consumer::new(
        [0x91; 32],
        "Human approval binding fixture".to_owned(),
        ObservedConsumerIdentity::new(Some("binding-fixture".to_owned()), None, None, None)
            .expect("identity"),
        timestamp(101),
    )
    .expect("consumer");
    runtime
        .device_state()
        .insert_consumer(&consumer)
        .expect("insert consumer");

    let expected_vault_id = VaultId::generate();
    let unlock = runtime
        .submit_approval(
            ApprovalSubject::Unlock {
                consumer_id: consumer.consumer_id(),
                vault_id: expected_vault_id,
            },
            timestamp(102),
            timestamp(1_000),
        )
        .expect("unlock approval");
    let unlock_id = unlock.receipt().approval_request_id();
    assert!(matches!(
        runtime.approve_pending_unlock(unlock_id, VaultId::generate(), timestamp(103)),
        Err(BrokerRuntimeError::Approval(
            BrokerApprovalError::ApprovalUnavailable
        ))
    ));
    assert_eq!(
        runtime
            .poll_approval(consumer.consumer_id(), unlock_id, timestamp(104))
            .expect("unlock remains pending")
            .status(),
        ApprovalStatus::Pending
    );

    let expected_capability = Capability::v1(CapabilityName::HttpRequest);
    let target = AuthorizationTarget::new(
        consumer.consumer_id(),
        CredentialFieldScope::new(
            expected_vault_id,
            CredentialId::generate(),
            SecretFieldId::generate(),
        ),
        expected_capability,
    );
    let access = runtime
        .submit_approval(
            ApprovalSubject::Access { target },
            timestamp(105),
            timestamp(1_000),
        )
        .expect("access approval");
    let access_id = access.receipt().approval_request_id();
    assert!(matches!(
        runtime.allow_once_pending_request(
            access_id,
            Some(BrokerCredentialCandidateSelection::new(
                CredentialId::generate(),
                SecretFieldId::generate(),
            )),
            timestamp(106),
        ),
        Err(BrokerRuntimeError::Approval(
            BrokerApprovalError::ApprovalUnavailable
        ))
    ));
    assert!(matches!(
        runtime.configure_pending_request_access_rule(
            access_id,
            None,
            Capability::v1(CapabilityName::ProcessRun),
            ConfirmationPolicy::EveryUse,
            RuleLifetime::Persistent,
            timestamp(107),
        ),
        Err(BrokerRuntimeError::Approval(
            BrokerApprovalError::ApprovalUnavailable
        ))
    ));
    assert_eq!(
        runtime
            .poll_approval(consumer.consumer_id(), access_id, timestamp(108))
            .expect("access remains pending")
            .status(),
        ApprovalStatus::Pending
    );
    runtime.shutdown_at(timestamp(109)).expect("shutdown");
}

#[test]
fn first_run_refuses_key_only_or_state_only_authority_without_replacement() {
    let key_only_home = TestHome::new("first-run-key-only");
    let key_only_store = MemoryKeyStore::default();
    DeviceKeyManager::new(key_only_store.clone())
        .initialize_new()
        .expect("key only");
    let key_before = key_only_store.bytes().expect("key bytes");

    let key_only_error = BrokerRuntime::open_or_initialize_with_paths_at(
        key_only_home.paths.clone(),
        key_only_store.clone(),
        timestamp(100),
    )
    .expect_err("key-only authority must fail");
    assert!(matches!(
        key_only_error,
        BrokerRuntimeError::LocalData(BrokerLocalDataError::DeviceState(DeviceStateError::Missing))
    ));
    assert_eq!(key_only_store.bytes().expect("preserved key"), key_before);
    assert!(!key_only_home.database_path().exists());

    let state_only_home = TestHome::new("first-run-state-only");
    let state_only_store = MemoryKeyStore::default();
    let state = initialize_state(&state_only_home, &state_only_store);
    drop(state);
    let state_before = fs::read(state_only_home.database_path()).expect("state bytes");
    state_only_store.forget();

    let state_only_error = BrokerRuntime::open_or_initialize_with_paths_at(
        state_only_home.paths.clone(),
        state_only_store.clone(),
        timestamp(100),
    )
    .expect_err("state-only authority must fail");
    assert!(matches!(
        state_only_error,
        BrokerRuntimeError::LocalData(BrokerLocalDataError::DeviceKey(DeviceKeyError::Missing))
    ));
    assert!(state_only_store.bytes().is_none());
    assert_eq!(
        fs::read(state_only_home.database_path()).expect("preserved state"),
        state_before
    );
}

#[test]
fn first_run_treats_a_lone_managed_sidecar_as_preserved_state() {
    let home = TestHome::new("first-run-sidecar");
    let key_store = MemoryKeyStore::default();
    let sidecar = home.paths.state().join("device-v1.db-wal");
    fs::write(&sidecar, b"incomplete encrypted state").expect("write sidecar");
    fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600)).expect("protect sidecar");
    let sidecar_before = fs::read(&sidecar).expect("sidecar bytes");

    let error = BrokerRuntime::open_or_initialize_with_paths_at(
        home.paths.clone(),
        key_store.clone(),
        timestamp(100),
    )
    .expect_err("incomplete state must block initialization");

    assert!(matches!(
        error,
        BrokerRuntimeError::LocalData(BrokerLocalDataError::DeviceKey(DeviceKeyError::Missing))
    ));
    assert!(key_store.bytes().is_none());
    assert!(!home.database_path().exists());
    assert_eq!(
        fs::read(sidecar).expect("preserved sidecar"),
        sidecar_before
    );
}

#[test]
fn restart_restores_authenticated_controls_but_discards_prior_process_grants() {
    let home = TestHome::new("restart");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    state
        .set_apps_tools_paused(true, timestamp(140))
        .expect("persist pause");

    let vault = home.create_vault("Restart");
    let prior_process = BrokerProcess::new().expect("prior process");
    let prior_process_id = prior_process.broker_instance_id();
    prior_process
        .vault_sessions()
        .open_vault(&vault.path)
        .expect("open vault");
    let unlocked = prior_process
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password)
        .expect("unlock vault");
    let prior_session_id = unlocked.vault_session_id().expect("unlock session");
    let (consumer, rule, _) = seed_authorization(&state, vault.vault_id, prior_session_id);
    drop(state);
    drop(prior_process);

    let mut restarted =
        BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store.clone()).expect("restart");

    assert_ne!(restarted.process().broker_instance_id(), prior_process_id);
    assert_eq!(restarted.stale_use_grants_removed(), 1);
    assert!(restarted
        .process()
        .vault_sessions()
        .snapshots()
        .expect("new sessions")
        .is_empty());
    assert_eq!(
        restarted
            .device_state()
            .consumer(consumer.consumer_id())
            .expect("consumer"),
        Some(consumer.clone())
    );
    assert_eq!(
        restarted
            .device_state()
            .access_rules_for_consumer(consumer.consumer_id())
            .expect("rules"),
        vec![rule]
    );
    assert!(restarted
        .device_state()
        .use_grants_for_consumer(consumer.consumer_id())
        .expect("grants")
        .is_empty());
    let paused = restarted
        .machine_access()
        .authorize_machine_operation()
        .expect_err("paused after restart");
    assert!(matches!(paused, BrokerMachineAccessError::Paused));
    assert_eq!(paused.broker_error_code(), BrokerErrorCode::BrokerPaused);
    let debug = format!("{restarted:?}");
    assert!(!debug.contains(home.path.to_string_lossy().as_ref()));
    assert!(!debug.contains("correct horse"));

    restarted.shutdown().expect("graceful shutdown");
    drop(restarted);
    let mut second =
        BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store).expect("second restart");
    assert_eq!(second.stale_use_grants_removed(), 0);
    assert!(second
        .machine_access()
        .is_paused()
        .expect("persisted pause"));
    second.shutdown().expect("second shutdown");
}

#[test]
fn restart_prunes_expired_encrypted_audit_before_exposing_the_runtime() {
    const DAY_MILLIS: i64 = 86_400_000;

    let home = TestHome::new("audit-retention-restart");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    state
        .set_audit_retention_days(1, timestamp(10 * DAY_MILLIS))
        .expect("configure retention");
    let event = AuditEvent::new(
        timestamp(10 * DAY_MILLIS),
        AuditEventKind::Authorization,
        AuditScope::default(),
        AuditDecision::Denied,
        ConfirmationMethod::None,
    );
    state.append_audit_event(&event).expect("append audit");
    assert_eq!(
        state.recent_audit_events(10).expect("audit before restart"),
        vec![event]
    );
    drop(state);

    let mut runtime = BrokerRuntime::reopen_with_paths_at(
        home.paths.clone(),
        key_store,
        timestamp(12 * DAY_MILLIS),
    )
    .expect("runtime");

    assert!(runtime
        .device_state()
        .recent_audit_events(10)
        .expect("audit after restart")
        .is_empty());
    runtime
        .shutdown_at(timestamp(12 * DAY_MILLIS))
        .expect("shutdown");
}

#[test]
fn trusted_audit_view_export_and_confirmed_clear_never_modify_the_portable_vault() {
    const RAW_SECRET_MARKER: &str = "KN_SECRET_63_128A";
    const CREDENTIAL_TITLE_MARKER: &str = "KN_TITLE_63_EA41";
    const URL_MARKER: &str = "https://kn-url-63.invalid/6c90";
    const REQUEST_BODY_MARKER: &str = "KN_REQ_BODY_63_901F";
    const COMMAND_ARGUMENTS_MARKER: &str = "KN_ARGS_63_4A62";
    const STANDARD_OUTPUT_MARKER: &str = "KN_STDOUT_63_D65C";
    const STANDARD_ERROR_MARKER: &str = "KN_STDERR_63_7F32";
    const RESPONSE_BODY_MARKER: &str = "KN_RESP_BODY_63_5B77";
    const EXECUTABLE_NAME_MARKER: &str = "KN_EXEC_63_9CD0";
    const FULL_EXECUTABLE_PATH: &str =
        "/Applications/KN_EXEC_PATH_63_339E.app/Contents/MacOS/agent";

    let home = TestHome::new("audit-control-plane");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    let vault = home.create_vault("AuditControlPlane");
    let mut unlocked = VaultCore::new()
        .open_vault(OpenVaultRequest {
            path: vault.path.clone(),
        })
        .expect("open marker fixture")
        .unlock(UnlockRequest {
            master_password: vault.password.clone(),
        })
        .expect("unlock marker fixture");
    let item = unlocked
        .create_item(VaultItemDraft {
            title: CREDENTIAL_TITLE_MARKER.to_owned(),
            content: VaultItemContent::Login(LoginItem {
                username: None,
                password: Some(SecretBytes::new(RAW_SECRET_MARKER.as_bytes().to_vec())),
                urls: vec![URL_MARKER.to_owned()],
                notes: None,
                totp_secret: None,
            }),
            tags: Vec::new(),
            favorite: false,
        })
        .expect("create marker credential");
    let credential_id: CredentialId = item.id.0.parse().expect("credential ID");
    let summary = unlocked
        .credential_summary(credential_id)
        .expect("credential summary")
        .expect("active credential");
    let secret_field_id = summary
        .secret_fields
        .iter()
        .find(|field| field.kind == SecretFieldKind::Password)
        .expect("password field")
        .secret_field_id;
    drop(unlocked.lock());

    let vault_metadata_path = vault.path.join("vault.json");
    let key_envelope_path = vault.path.join("keys.enc");
    let metadata_before = fs::read(&vault_metadata_path).expect("vault metadata");
    let key_envelope_before = fs::read(&key_envelope_path).expect("key envelope");
    assert!(
        ObservedConsumerIdentity::new(Some(FULL_EXECUTABLE_PATH.to_owned()), None, None, None,)
            .is_err()
    );
    let consumer = Consumer::new(
        [0x63; 32],
        [
            REQUEST_BODY_MARKER,
            COMMAND_ARGUMENTS_MARKER,
            STANDARD_OUTPUT_MARKER,
            STANDARD_ERROR_MARKER,
            RESPONSE_BODY_MARKER,
        ]
        .join("|"),
        ObservedConsumerIdentity::new(Some(EXECUTABLE_NAME_MARKER.to_owned()), None, None, None)
            .expect("path-free observed identity"),
        timestamp(140),
    )
    .expect("Consumer");
    let consumer_id = consumer.consumer_id();
    state.insert_consumer(&consumer).expect("insert Consumer");
    let event = AuditEvent::new(
        timestamp(150),
        AuditEventKind::CredentialUse,
        AuditScope::new(
            Some(consumer_id),
            Some(CredentialFieldScope::new(
                vault.vault_id,
                credential_id,
                secret_field_id,
            )),
            Some(Capability::v1(CapabilityName::HttpRequest)),
            None,
        ),
        AuditDecision::Failed,
        ConfirmationMethod::PersistentRule,
    );
    state.append_audit_event(&event).expect("append audit");
    drop(state);

    let mut runtime =
        BrokerRuntime::reopen_with_paths_at(home.paths.clone(), key_store, timestamp(200))
            .expect("runtime");
    let filter = BrokerAuditFilter::all()
        .with_consumer(consumer_id)
        .with_event_kind(AuditEventKind::CredentialUse);
    let page = runtime
        .view_audit_at(filter, None, 10, timestamp(200))
        .expect("view audit");
    assert_eq!(page.events(), std::slice::from_ref(&event));
    assert_eq!(page.next_cursor(), None);
    let export = runtime
        .export_audit_json_at(filter, timestamp(200))
        .expect("export audit");
    assert_eq!(export.event_count(), 1);
    let audit_output = format!("{page:?}\n{export:?}\n{}", export.as_str());
    for marker in [
        RAW_SECRET_MARKER,
        CREDENTIAL_TITLE_MARKER,
        URL_MARKER,
        REQUEST_BODY_MARKER,
        COMMAND_ARGUMENTS_MARKER,
        STANDARD_OUTPUT_MARKER,
        STANDARD_ERROR_MARKER,
        RESPONSE_BODY_MARKER,
        EXECUTABLE_NAME_MARKER,
        FULL_EXECUTABLE_PATH,
    ] {
        assert!(
            !audit_output.contains(marker),
            "audit output leaked {marker}"
        );
    }
    assert!(!audit_output.contains(vault.path.to_string_lossy().as_ref()));

    let cleared = runtime
        .clear_audit(
            filter,
            BrokerAuditClearConfirmation::after_user_confirmation(filter),
        )
        .expect("clear audit");
    assert_eq!(cleared.removed_events(), 1);
    assert_eq!(cleared.remaining_events(), 0);
    assert_eq!(
        fs::read(vault_metadata_path).expect("vault metadata after clear"),
        metadata_before
    );
    assert_eq!(
        fs::read(key_envelope_path).expect("key envelope after clear"),
        key_envelope_before
    );
    runtime.shutdown_at(timestamp(210)).expect("shutdown");
}

#[test]
fn portable_backup_and_plaintext_export_exclude_device_state_and_local_unlock() {
    const PROFILE_LABEL: &str = "KN_DEVICE_PROFILE_11_4";

    let home = TestHome::new("portable-device-boundary");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    let vault = home.create_vault("PortableBoundary");
    let vault_session_id = VaultSessionId::generate();
    let (consumer, rule, grant) = seed_authorization(&state, vault.vault_id, vault_session_id);
    let profile = UsageProfile::new(
        consumer.consumer_id(),
        PROFILE_LABEL.to_owned(),
        Capability::v1(CapabilityName::ProcessRun),
        UsagePlacement::ProcessStdin {
            append_newline: false,
        },
        timestamp(140),
    )
    .expect("Usage Profile");
    state
        .insert_usage_profile(&profile)
        .expect("insert Usage Profile");
    let target = rule.target();
    let audit = AuditEvent::new(
        timestamp(150),
        AuditEventKind::CredentialUse,
        AuditScope::new(
            Some(consumer.consumer_id()),
            Some(target.field_scope()),
            Some(target.capability()),
            Some(grant.use_grant_id()),
        ),
        AuditDecision::Allowed,
        ConfirmationMethod::PersistentRule,
    );
    state.append_audit_event(&audit).expect("append audit");
    state
        .set_apps_tools_paused(true, timestamp(160))
        .expect("pause machine access");
    assert!(home.database_path().is_file());

    let mut unlocked = VaultCore::new()
        .open_vault(OpenVaultRequest {
            path: vault.path.clone(),
        })
        .expect("open vault")
        .unlock(UnlockRequest {
            master_password: vault.password.clone(),
        })
        .expect("unlock vault");
    unlocked
        .create_credential(CredentialDraft {
            title: "Portable API token".to_owned(),
            template_id: Some("api-token".to_owned()),
            fields: vec![CredentialField::secret(
                "token",
                SecretFieldKind::ApiToken,
                SecretBytes::new(b"portable-secret".to_vec()),
            )],
            tags: vec!["portable".to_owned()],
            favorite: false,
        })
        .expect("create portable credential");
    let _local_unlock_material = unlocked
        .local_unlock_material()
        .expect("create local unlock material");
    assert!(vault.path.join("local_unlock.enc").is_file());

    let backup_path = home.path.join("PortableBackup.pswvault");
    unlocked
        .backup_to(backup_path.clone())
        .expect("create portable backup");
    let export_path = home.path.join("portable-export.json");
    unlocked
        .export_items(ExportItemsRequest {
            destination_path: export_path.clone(),
            export_format: "keptnear-json".to_owned(),
            current_master_password: vault.password.clone(),
        })
        .expect("create plaintext export");

    let mut backup_root_entries = fs::read_dir(&backup_path)
        .expect("read backup root")
        .map(|entry| {
            entry
                .expect("backup root entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    backup_root_entries.sort();
    assert_eq!(
        backup_root_entries,
        [
            "attachments",
            "items",
            "keys.enc",
            "tombstones",
            "vault.json"
        ]
    );
    assert!(!backup_path.join("local_unlock.enc").exists());
    assert!(!backup_path.join(".keptnear").exists());

    let export_bytes = fs::read(&export_path).expect("read plaintext export");
    let export_json: serde_json::Value =
        serde_json::from_slice(&export_bytes).expect("parse plaintext export");
    let mut export_root_fields = export_json
        .as_object()
        .expect("export object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    export_root_fields.sort();
    assert_eq!(
        export_root_fields,
        [
            "format",
            "items",
            "omissions",
            "sourceVaultId",
            "version",
            "warning",
        ]
    );

    let backup_bytes = read_directory_tree_bytes(&backup_path);
    let export_text = String::from_utf8(export_bytes).expect("UTF-8 export");
    for device_state_marker in [
        consumer.consumer_id().to_string(),
        rule.access_rule_id().to_string(),
        grant.use_grant_id().to_string(),
        profile.usage_profile_id().to_string(),
        audit.audit_event_id().to_string(),
        PROFILE_LABEL.to_owned(),
        "Restart integration Consumer".to_owned(),
        DEVICE_STATE_DATABASE_FILENAME.to_owned(),
        "access_rules".to_owned(),
        "use_grants".to_owned(),
        "usage_profiles".to_owned(),
        "audit_events".to_owned(),
    ] {
        assert!(!export_text.contains(&device_state_marker));
        assert!(!backup_bytes
            .windows(device_state_marker.len())
            .any(|window| window == device_state_marker.as_bytes()));
    }

    assert_eq!(
        state
            .consumer(consumer.consumer_id())
            .expect("reload Consumer"),
        Some(consumer)
    );
    assert_eq!(
        state
            .access_rules_for_consumer(rule.target().consumer_id())
            .expect("reload Access Rule"),
        vec![rule]
    );
    assert_eq!(
        state
            .use_grants_for_consumer(grant.target().consumer_id())
            .expect("reload Use Grant"),
        vec![grant]
    );
    assert_eq!(
        state
            .usage_profiles_for_consumer(profile.consumer_id())
            .expect("reload Usage Profile"),
        vec![profile]
    );
    assert_eq!(
        state.recent_audit_events(10).expect("reload audit"),
        vec![audit]
    );
    assert!(state.apps_tools_paused().expect("reload pause state"));
}

#[test]
fn graceful_shutdown_revokes_live_session_grants_before_restart() {
    let home = TestHome::new("graceful");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    drop(state);
    let mut runtime =
        BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store.clone()).expect("runtime");
    let vault = home.create_vault("Graceful");
    runtime
        .process()
        .vault_sessions()
        .open_vault(&vault.path)
        .expect("open vault");
    let unlocked = runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password)
        .expect("unlock vault");
    let session_id = unlocked.vault_session_id().expect("session");
    let (consumer, rule, _) =
        seed_authorization(runtime.device_state(), vault.vault_id, session_id);

    let summary = runtime.shutdown().expect("shutdown");

    assert_eq!(summary.use_grants_removed(), 1);
    assert!(runtime
        .process()
        .vault_sessions()
        .is_shutdown()
        .expect("session shutdown"));
    assert!(runtime
        .device_state()
        .use_grants_for_consumer(consumer.consumer_id())
        .expect("grants")
        .is_empty());
    assert_eq!(
        runtime
            .device_state()
            .access_rules_for_consumer(consumer.consumer_id())
            .expect("rules"),
        vec![rule]
    );
    assert_eq!(
        runtime
            .shutdown()
            .expect("idempotent shutdown")
            .use_grants_removed(),
        0
    );
    drop(runtime);

    let mut restarted =
        BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store).expect("restart");
    assert_eq!(restarted.stale_use_grants_removed(), 0);
    restarted.shutdown().expect("restart shutdown");
}

#[test]
fn restart_and_shutdown_cancel_process_local_pairing_requests() {
    let home = TestHome::new("pairing-lifecycle");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    drop(state);
    let signing_key = SigningKey::from_bytes(&[0x51; 32]);
    let proposal = || {
        ConsumerPairingProposal::new(
            signing_key.verifying_key().to_bytes(),
            [0x52; crate::PAIRING_NONCE_LENGTH],
            crate::BrokerProtocolVersion::current(),
        )
        .expect("pairing proposal")
    };
    let observed_identity = || {
        ObservedConsumerIdentity::new(
            Some("integration-adapter".to_owned()),
            Some("app.keptnear.integration".to_owned()),
            None,
            Some([0x53; 32]),
        )
        .expect("observed identity")
    };

    let runtime =
        BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store.clone()).expect("runtime");
    runtime
        .begin_pairing(proposal(), observed_identity())
        .expect("pending pairing");
    assert_eq!(
        runtime.pending_pairings().expect("pending requests")[0].status(),
        BrokerPairingRequestStatus::AwaitingUserApproval
    );
    drop(runtime);

    let mut restarted =
        BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store).expect("restart");
    assert!(restarted
        .pending_pairings()
        .expect("requests after restart")
        .is_empty());
    restarted
        .begin_pairing(proposal(), observed_identity())
        .expect("new request after restart");
    restarted.shutdown().expect("shutdown");
    assert!(restarted
        .pending_pairings()
        .expect("requests after shutdown")
        .is_empty());
}

#[test]
fn human_pending_queue_unifies_pairing_unlock_and_field_access_without_paths() {
    let home = TestHome::new("human-pending-queue");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("current timestamp");
    let consumer = Consumer::new(
        [0x54; 32],
        "Queue Consumer".to_owned(),
        ObservedConsumerIdentity::new(
            Some("queue-adapter".to_owned()),
            Some("app.keptnear.queue".to_owned()),
            None,
            Some([0x55; 32]),
        )
        .expect("identity"),
        timestamp(now_ms - 1_000),
    )
    .expect("consumer");
    state.insert_consumer(&consumer).expect("insert consumer");
    drop(state);

    let runtime =
        BrokerRuntime::reopen_with_paths_at(home.paths.clone(), key_store, timestamp(now_ms))
            .expect("runtime");
    let pairing_key = SigningKey::from_bytes(&[0x56; 32]);
    let pairing = runtime
        .begin_pairing(
            ConsumerPairingProposal::new(
                pairing_key.verifying_key().to_bytes(),
                [0x57; crate::PAIRING_NONCE_LENGTH],
                BrokerProtocolVersion::current(),
            )
            .expect("proposal"),
            ObservedConsumerIdentity::new(
                Some("pending-adapter".to_owned()),
                Some("app.keptnear.pending".to_owned()),
                None,
                Some([0x58; 32]),
            )
            .expect("pending identity"),
        )
        .expect("pairing");
    runtime
        .submit_approval(
            ApprovalSubject::Unlock {
                consumer_id: consumer.consumer_id(),
                vault_id: VaultId::generate(),
            },
            timestamp(now_ms),
            timestamp(now_ms + 60_000),
        )
        .expect("unlock approval");
    let field_scope = CredentialFieldScope::new(
        VaultId::generate(),
        CredentialId::generate(),
        SecretFieldId::generate(),
    );
    runtime
        .submit_approval(
            ApprovalSubject::Access {
                target: AuthorizationTarget::new(
                    consumer.consumer_id(),
                    field_scope,
                    Capability::v1(CapabilityName::ProcessRun),
                ),
            },
            timestamp(now_ms + 1),
            timestamp(now_ms + 90_000),
        )
        .expect("access approval");

    let queue = runtime
        .pending_requests_for_human()
        .expect("pending request queue");
    assert_eq!(queue.pending_count(), 3);
    assert!(matches!(
        queue.requests()[0].request_id(),
        BrokerPendingRequestId::Pairing(_)
    ));
    assert_eq!(
        queue.requests()[0].kind(),
        BrokerPendingRequestKind::Pairing
    );
    assert_eq!(
        queue.requests()[0]
            .identity_evidence()
            .and_then(|identity| identity.executable_name()),
        Some("pending-adapter")
    );
    assert!(queue.requests()[0].pairing_comparison_code().is_some());
    assert!(queue.requests()[0].pairing_key_fingerprint().is_some());
    assert_eq!(queue.requests()[1].kind(), BrokerPendingRequestKind::Unlock);
    assert_eq!(queue.requests()[1].consumer_label(), Some("Queue Consumer"));
    assert_eq!(queue.requests()[2].kind(), BrokerPendingRequestKind::Access);
    assert_eq!(queue.requests()[2].field_scope(), Some(field_scope));
    assert!(!format!("{queue:?}").contains(home.path.to_string_lossy().as_ref()));

    runtime
        .approve_pairing(
            pairing.pairing_request_id(),
            BrokerPairingUserApproval::after_user_approval(
                "Approved Consumer".to_owned(),
                timestamp(now_ms + 2),
            ),
        )
        .expect("approve pairing");
    let after_pairing_approval = runtime
        .pending_requests_for_human()
        .expect("queue after pairing approval");
    assert_eq!(after_pairing_approval.pending_count(), 2);
    assert!(after_pairing_approval
        .requests()
        .iter()
        .all(|request| request.kind() != BrokerPendingRequestKind::Pairing));
}

#[test]
fn first_request_actions_deny_and_allow_once_without_creating_access_rules() {
    let home = TestHome::new("first-request-actions");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("current timestamp");
    let consumer = Consumer::new(
        [0x59; 32],
        "First Request Consumer".to_owned(),
        ObservedConsumerIdentity::default(),
        timestamp(now_ms - 1_000),
    )
    .expect("consumer");
    state.insert_consumer(&consumer).expect("insert consumer");
    drop(state);

    let vault = home.create_vault("FirstRequest");
    let mut unlocked = VaultCore::new()
        .open_vault(OpenVaultRequest {
            path: vault.path.clone(),
        })
        .expect("open fixture")
        .unlock(UnlockRequest {
            master_password: vault.password.clone(),
        })
        .expect("unlock fixture");
    unlocked
        .create_item(VaultItemDraft {
            title: "Release API token".to_owned(),
            content: VaultItemContent::Login(LoginItem {
                username: Some("release-account".to_owned()),
                password: Some(SecretBytes::new(b"seeded-secret-marker".to_vec())),
                urls: Vec::new(),
                notes: None,
                totp_secret: None,
            }),
            tags: vec!["release".to_owned()],
            favorite: false,
        })
        .expect("credential");
    drop(unlocked.lock());

    let mut runtime =
        BrokerRuntime::reopen_with_paths_at(home.paths.clone(), key_store, timestamp(now_ms))
            .expect("runtime");
    runtime
        .process()
        .vault_sessions()
        .open_vault(&vault.path)
        .expect("open broker vault");
    let vault_session_id = runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password)
        .expect("unlock broker vault")
        .vault_session_id()
        .expect("vault session");
    let summaries = runtime
        .process()
        .vault_sessions()
        .matching_credential_summaries(vault.vault_id, vault_session_id, "Release API token")
        .expect("credential summary");
    let summary = summaries.first().expect("matching credential");
    let secret_field = summary.secret_fields.first().expect("secret field");
    let target = AuthorizationTarget::new(
        consumer.consumer_id(),
        CredentialFieldScope::new(
            vault.vault_id,
            summary.credential_id,
            secret_field.secret_field_id,
        ),
        Capability::v1(CapabilityName::ProcessRun),
    );

    let exact = runtime
        .submit_approval(
            ApprovalSubject::Access { target },
            timestamp(now_ms + 1),
            timestamp(now_ms + 60_000),
        )
        .expect("exact approval");
    let exact_id = exact.receipt().approval_request_id();
    let exact_grant = runtime
        .allow_once_pending_request(exact_id, None, timestamp(now_ms + 2))
        .expect("Allow Once");
    assert_eq!(exact_grant.basis(), BrokerUseGrantBasis::AllowOnce);
    assert_eq!(exact_grant.grant().scope(), GrantScope::OneOperation);
    assert_eq!(exact_grant.grant().expires_at(), timestamp(now_ms + 60_000));
    assert_eq!(
        runtime
            .poll_approval(consumer.consumer_id(), exact_id, timestamp(now_ms + 3))
            .expect("approved receipt")
            .status(),
        ApprovalStatus::Approved
    );
    assert!(runtime
        .device_state()
        .access_rules_for_consumer(consumer.consumer_id())
        .expect("rules")
        .is_empty());

    let denied = runtime
        .submit_approval(
            ApprovalSubject::Access { target },
            timestamp(now_ms + 4),
            timestamp(now_ms + 60_000),
        )
        .expect("denied approval");
    let denied_id = denied.receipt().approval_request_id();
    runtime
        .deny_pending_request(
            BrokerPendingRequestId::Approval(denied_id),
            timestamp(now_ms + 5),
        )
        .expect("deny request");
    assert_eq!(
        runtime
            .poll_approval(consumer.consumer_id(), denied_id, timestamp(now_ms + 6))
            .expect("denied receipt")
            .status(),
        ApprovalStatus::Denied
    );

    let admitted = runtime
        .admit_new_credential_request(
            BrokerNewCredentialRequest::new(
                consumer.consumer_id(),
                vault.vault_id,
                Capability::v1(CapabilityName::ProcessRun),
                "release api token".to_owned(),
            )
            .expect("new credential request"),
        )
        .expect("admit request");
    let new_credential = runtime
        .submit_new_credential_approval(admitted, timestamp(now_ms + 7), timestamp(now_ms + 60_000))
        .expect("new credential approval");
    let new_credential_id = new_credential.receipt().approval_request_id();
    assert!(runtime
        .allow_once_pending_request(new_credential_id, None, timestamp(now_ms + 8))
        .is_err());
    let review = runtime
        .review_pending_new_credential_for_current_session(new_credential_id, timestamp(now_ms + 9))
        .expect("candidate review");
    let candidate = review.candidates().first().expect("candidate");
    let candidate_field = candidate.secret_fields().first().expect("candidate field");
    let selection = BrokerCredentialCandidateSelection::new(
        candidate.credential_id(),
        candidate_field.secret_field_id(),
    );
    let selected_grant = runtime
        .allow_once_pending_request(new_credential_id, Some(selection), timestamp(now_ms + 10))
        .expect("selected Allow Once");
    assert_eq!(selected_grant.basis(), BrokerUseGrantBasis::AllowOnce);
    assert_eq!(
        runtime
            .poll_approval(
                consumer.consumer_id(),
                new_credential_id,
                timestamp(now_ms + 11),
            )
            .expect("selected receipt")
            .status(),
        ApprovalStatus::Approved
    );
    assert_eq!(
        runtime
            .device_state()
            .use_grants_for_consumer(consumer.consumer_id())
            .expect("grants")
            .len(),
        2
    );
    assert!(runtime
        .device_state()
        .access_rules_for_consumer(consumer.consumer_id())
        .expect("rules")
        .is_empty());

    let persistent = runtime
        .submit_approval(
            ApprovalSubject::Access { target },
            timestamp(now_ms + 12),
            timestamp(now_ms + 60_000),
        )
        .expect("persistent approval");
    let persistent_id = persistent.receipt().approval_request_id();
    let bounded_rule_lifetime = RuleLifetime::Until(timestamp(now_ms + 120_000));
    let creation = runtime
        .configure_pending_request_access_rule(
            persistent_id,
            None,
            target.capability(),
            ConfirmationPolicy::EveryUse,
            bounded_rule_lifetime,
            timestamp(now_ms + 13),
        )
        .expect("persistent Access Rule");
    assert!(creation.newly_created());
    assert_eq!(
        creation.rule().confirmation_policy(),
        ConfirmationPolicy::EveryUse
    );
    assert_eq!(creation.rule().lifetime(), bounded_rule_lifetime);
    assert_eq!(
        runtime
            .poll_approval(
                consumer.consumer_id(),
                persistent_id,
                timestamp(now_ms + 14),
            )
            .expect("persistent receipt")
            .status(),
        ApprovalStatus::Approved
    );
    assert_eq!(
        runtime
            .device_state()
            .use_grants_for_consumer(consumer.consumer_id())
            .expect("persistent rule issues no grant")
            .len(),
        2
    );

    let repeated = runtime
        .submit_approval(
            ApprovalSubject::Access { target },
            timestamp(now_ms + 15),
            timestamp(now_ms + 60_000),
        )
        .expect("repeat persistent approval");
    let repeated_id = repeated.receipt().approval_request_id();
    let repeated_creation = runtime
        .configure_pending_request_access_rule(
            repeated_id,
            None,
            target.capability(),
            ConfirmationPolicy::EveryUse,
            bounded_rule_lifetime,
            timestamp(now_ms + 16),
        )
        .expect("idempotent persistent Access Rule");
    assert!(!repeated_creation.newly_created());
    assert_eq!(
        repeated_creation.rule().access_rule_id(),
        creation.rule().access_rule_id()
    );

    let conflicting = runtime
        .submit_approval(
            ApprovalSubject::Access { target },
            timestamp(now_ms + 17),
            timestamp(now_ms + 60_000),
        )
        .expect("conflicting persistent approval");
    let conflicting_id = conflicting.receipt().approval_request_id();
    assert!(runtime
        .configure_pending_request_access_rule(
            conflicting_id,
            None,
            target.capability(),
            ConfirmationPolicy::AutomaticWhileUnlocked,
            bounded_rule_lifetime,
            timestamp(now_ms + 18),
        )
        .is_err());
    assert_eq!(
        runtime
            .poll_approval(
                consumer.consumer_id(),
                conflicting_id,
                timestamp(now_ms + 19),
            )
            .expect("conflicting request remains pending")
            .status(),
        ApprovalStatus::Pending
    );
    assert_eq!(
        runtime
            .device_state()
            .access_rules_for_consumer(consumer.consumer_id())
            .expect("one persistent rule")
            .len(),
        1
    );
    runtime
        .deny_pending_request(
            BrokerPendingRequestId::Approval(conflicting_id),
            timestamp(now_ms + 20),
        )
        .expect("clean conflicting request");

    runtime.shutdown().expect("shutdown");
}

#[test]
fn completed_pairing_does_not_enable_credential_metadata_capabilities() {
    let home = TestHome::new("pairing-no-access");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    drop(state);
    let runtime = BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store).expect("runtime");
    let signing_key = SigningKey::from_bytes(&[0x61; 32]);
    let challenge = runtime
        .begin_pairing(
            ConsumerPairingProposal::new(
                signing_key.verifying_key().to_bytes(),
                [0x62; crate::PAIRING_NONCE_LENGTH],
                BrokerProtocolVersion::current(),
            )
            .expect("proposal"),
            ObservedConsumerIdentity::new(
                Some("integration-adapter".to_owned()),
                Some("app.keptnear.integration".to_owned()),
                None,
                None,
            )
            .expect("observed identity"),
        )
        .expect("pending pairing");
    let proof_challenge = runtime
        .approve_pairing(
            challenge.pairing_request_id(),
            BrokerPairingUserApproval::after_user_approval(
                "Metadata-free Consumer".to_owned(),
                timestamp(600),
            ),
        )
        .expect("approve pairing");
    let completion = runtime
        .complete_pairing(
            challenge.pairing_request_id(),
            signing_key.sign(proof_challenge.transcript()).to_bytes(),
        )
        .expect("complete pairing");

    assert_eq!(
        completion.authorization_effect(),
        BrokerPairingAuthorizationEffect::Unchanged
    );
    assert!(runtime
        .device_state()
        .access_rules_for_consumer(completion.consumer_id())
        .expect("rules")
        .is_empty());
    assert!(runtime
        .device_state()
        .use_grants_for_consumer(completion.consumer_id())
        .expect("grants")
        .is_empty());

    let hello = BrokerRequestEnvelope::new(
        BrokerProtocolVersion::current(),
        BrokerRequestId::generate(),
        BrokerRequest::Hello(
            BrokerHelloRequest::new(
                vec![BrokerProtocolVersionRange::new(1, 0, 0).expect("range")],
                vec![
                    BrokerCapabilityVersions::new(CapabilityName::CredentialSearch, [1])
                        .expect("capability"),
                ],
            )
            .expect("hello"),
        ),
    );
    let mut connection = crate::BrokerConnectionState::awaiting_hello();
    let outcome = runtime
        .process()
        .dispatcher()
        .dispatch(
            &mut connection,
            &encode_broker_request(&hello).expect("encode hello"),
        )
        .expect("dispatch hello");
    let response = decode_broker_response(outcome.response_payload()).expect("decode response");
    let BrokerResponse::Hello(hello) = response.response() else {
        panic!("hello response");
    };
    assert_eq!(hello.capabilities().len(), 1);
    assert_eq!(
        hello.capabilities()[0].capability_name(),
        CapabilityName::CredentialSearch
    );
    assert_eq!(hello.capabilities()[0].version(), 1);
}

#[test]
fn machine_capability_dispatch_requires_negotiation_and_connection_authentication() {
    let home = TestHome::new("protocol-capability-gates");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    drop(state);
    let runtime = BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store).expect("runtime");
    let observed_identity =
        ObservedConsumerIdentity::new(Some("keptnear-mcp".to_owned()), None, None, None)
            .expect("observed identity");
    let dispatch = |connection: &mut crate::BrokerConnectionState, request: BrokerRequest| {
        let envelope = BrokerRequestEnvelope::new(
            BrokerProtocolVersion::current(),
            BrokerRequestId::generate(),
            request,
        );
        let outcome = runtime
            .process()
            .dispatcher()
            .dispatch_runtime(
                &runtime,
                &observed_identity,
                connection,
                &encode_broker_request(&envelope).expect("encode request"),
            )
            .expect("dispatch");
        decode_broker_response(outcome.response_payload()).expect("response")
    };

    let mut unsupported_connection = crate::BrokerConnectionState::awaiting_hello();
    assert!(matches!(
        dispatch(
            &mut unsupported_connection,
            BrokerRequest::Hello(
                BrokerHelloRequest::new(
                    vec![BrokerProtocolVersionRange::new(1, 0, 0).expect("range")],
                    vec![],
                )
                .expect("hello"),
            ),
        )
        .response(),
        BrokerResponse::Hello(_)
    ));
    let unsupported = dispatch(
        &mut unsupported_connection,
        BrokerRequest::GrantStatus(BrokerGrantStatusRequest::new(UseGrantId::generate())),
    );
    assert!(matches!(
        unsupported.response(),
        BrokerResponse::Error(error)
            if error.error_code() == BrokerErrorCode::UnsupportedCapability
    ));

    let mut unauthenticated_connection = crate::BrokerConnectionState::awaiting_hello();
    assert!(matches!(
        dispatch(
            &mut unauthenticated_connection,
            BrokerRequest::Hello(
                BrokerHelloRequest::new(
                    vec![BrokerProtocolVersionRange::new(1, 0, 0).expect("range")],
                    vec![
                        BrokerCapabilityVersions::new(CapabilityName::GrantStatus, [1])
                            .expect("capability"),
                    ],
                )
                .expect("hello"),
            ),
        )
        .response(),
        BrokerResponse::Hello(_)
    ));
    let unauthenticated = dispatch(
        &mut unauthenticated_connection,
        BrokerRequest::GrantStatus(BrokerGrantStatusRequest::new(UseGrantId::generate())),
    );
    assert!(matches!(
        unauthenticated.response(),
        BrokerResponse::Error(error)
            if error.error_code() == BrokerErrorCode::AuthenticationFailed
    ));
}

#[test]
fn runtime_protocol_pairs_then_authenticates_one_connection_without_granting_access() {
    let home = TestHome::new("protocol-pair-auth");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    drop(state);
    let runtime = BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store).expect("runtime");
    let observed_identity =
        ObservedConsumerIdentity::new(Some("keptnear-mcp".to_owned()), None, None, None)
            .expect("observed identity");
    let signing_key = SigningKey::from_bytes(&[0x6a; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    let client_nonce = [0x6b; crate::PAIRING_NONCE_LENGTH];
    let mut connection = crate::BrokerConnectionState::awaiting_hello();
    let dispatch = |connection: &mut crate::BrokerConnectionState, request: BrokerRequest| {
        let envelope = BrokerRequestEnvelope::new(
            BrokerProtocolVersion::current(),
            BrokerRequestId::generate(),
            request,
        );
        let outcome = runtime
            .process()
            .dispatcher()
            .dispatch_runtime(
                &runtime,
                &observed_identity,
                connection,
                &encode_broker_request(&envelope).expect("encode request"),
            )
            .expect("dispatch");
        (
            decode_broker_response(outcome.response_payload()).expect("response"),
            outcome.should_close_connection(),
        )
    };

    let (hello, close) = dispatch(
        &mut connection,
        BrokerRequest::Hello(
            BrokerHelloRequest::new(
                vec![BrokerProtocolVersionRange::new(1, 0, 0).expect("range")],
                vec![
                    BrokerCapabilityVersions::new(CapabilityName::AccessRequest, [1])
                        .expect("access capability"),
                    BrokerCapabilityVersions::new(CapabilityName::HttpRequest, [1])
                        .expect("HTTP capability"),
                ],
            )
            .expect("hello"),
        ),
    );
    assert!(matches!(hello.response(), BrokerResponse::Hello(_)));
    assert!(!close);
    assert!(!connection.is_authenticated());

    let (pending, close) = dispatch(
        &mut connection,
        BrokerRequest::PairingStart(BrokerPairingStartRequest::new(public_key, client_nonce)),
    );
    assert!(!close);
    let BrokerResponse::PairingProgress(BrokerPairingProgressResponse::Pending(pending)) =
        pending.response()
    else {
        panic!("pending pairing response");
    };
    assert_eq!(
        pending.status(),
        BrokerPairingRequestStatus::AwaitingUserApproval
    );
    assert_eq!(pending.consumer_id(), None);
    let pairing_request_id = pending.pairing_request_id();
    assert!(runtime
        .device_state()
        .consumers()
        .expect("consumers")
        .is_empty());
    let (resumed, close) = dispatch(
        &mut connection,
        BrokerRequest::PairingStart(BrokerPairingStartRequest::new(
            public_key,
            [0x6c; crate::PAIRING_NONCE_LENGTH],
        )),
    );
    assert!(!close);
    let BrokerResponse::PairingProgress(BrokerPairingProgressResponse::Pending(resumed)) =
        resumed.response()
    else {
        panic!("resumed pairing response");
    };
    assert_eq!(resumed.pairing_request_id(), pairing_request_id);
    assert_eq!(resumed.client_nonce(), &client_nonce);

    let proof_challenge = runtime
        .approve_pairing(
            pairing_request_id,
            BrokerPairingUserApproval::after_user_approval(
                "Local MCP adapter".to_owned(),
                timestamp(700),
            ),
        )
        .expect("local approval");
    let (proof_required, close) = dispatch(
        &mut connection,
        BrokerRequest::PairingStatus(BrokerPairingStatusRequest::new(
            pairing_request_id,
            public_key,
        )),
    );
    assert!(!close);
    let BrokerResponse::PairingProgress(BrokerPairingProgressResponse::Pending(proof_required)) =
        proof_required.response()
    else {
        panic!("proof-required response");
    };
    assert_eq!(
        proof_required.status(),
        BrokerPairingRequestStatus::AwaitingProof
    );
    let consumer_id = proof_required.consumer_id().expect("approved Consumer");
    assert_eq!(consumer_id, proof_challenge.consumer_id());
    let pairing_proof = signing_key
        .sign(&crate::consumer_pairing_transcript(
            BrokerProtocolVersion::current(),
            pairing_request_id,
            consumer_id,
            &public_key,
            proof_required.client_nonce(),
            proof_required.server_nonce(),
        ))
        .to_bytes();
    let (paired, close) = dispatch(
        &mut connection,
        BrokerRequest::PairingComplete(BrokerPairingCompleteRequest::new(
            pairing_request_id,
            pairing_proof,
        )),
    );
    assert!(!close);
    assert!(matches!(
        paired.response(),
        BrokerResponse::PairingComplete(_)
    ));
    assert!(!connection.is_authenticated());

    let (authentication_challenge, close) = dispatch(
        &mut connection,
        BrokerRequest::AuthenticationStart(BrokerAuthenticationStartRequest::new(consumer_id)),
    );
    assert!(!close);
    let BrokerResponse::AuthenticationChallenge(authentication_challenge) =
        authentication_challenge.response()
    else {
        panic!("authentication challenge");
    };
    let session_id = authentication_challenge.session_id();
    let authentication_proof = signing_key
        .sign(&crate::broker_authentication_transcript(
            BrokerProtocolVersion::current(),
            session_id,
            consumer_id,
            &public_key,
            authentication_challenge.broker_nonce(),
        ))
        .to_bytes();
    let proof_request =
        BrokerAuthenticationCompleteRequest::new(session_id, consumer_id, authentication_proof);
    let (authenticated, close) = dispatch(
        &mut connection,
        BrokerRequest::AuthenticationComplete(proof_request.clone()),
    );
    assert!(!close);
    assert!(matches!(
        authenticated.response(),
        BrokerResponse::Authenticated(_)
    ));
    assert_eq!(
        connection.authenticated_session(),
        Some((session_id, consumer_id))
    );

    let field_scope = CredentialFieldScope::new(
        VaultId::generate(),
        CredentialId::generate(),
        SecretFieldId::generate(),
    );
    let (submitted, close) = dispatch(
        &mut connection,
        BrokerRequest::AccessRequest(
            BrokerAccessRequest::exact(field_scope, Capability::v1(CapabilityName::HttpRequest))
                .expect("exact request"),
        ),
    );
    assert!(!close);
    let BrokerResponse::AccessRequest(BrokerAccessResponse::Submission(submission)) =
        submitted.response()
    else {
        panic!("access submission");
    };
    let approval_request_id = submission.approval_request_id();
    assert_eq!(submission.status(), ApprovalStatus::Pending);
    let pending = runtime
        .pending_approvals_for_human(timestamp(submission.expires_at().unix_millis() - 1))
        .expect("human approval queue")
        .into_iter()
        .find(|request| request.approval_request_id() == approval_request_id)
        .expect("submitted approval");
    let ApprovalSubject::Access { target } = pending.subject() else {
        panic!("exact access subject");
    };
    assert_eq!(target.consumer_id(), consumer_id);
    assert_eq!(target.field_scope(), field_scope);

    let (status, close) = dispatch(
        &mut connection,
        BrokerRequest::AccessRequest(BrokerAccessRequest::status(approval_request_id)),
    );
    assert!(!close);
    assert!(matches!(
        status.response(),
        BrokerResponse::AccessRequest(BrokerAccessResponse::Status(receipt))
            if receipt.approval_request_id() == approval_request_id
                && receipt.status() == ApprovalStatus::Pending
    ));

    let (resumed, close) = dispatch(
        &mut connection,
        BrokerRequest::AccessRequest(BrokerAccessRequest::resume(approval_request_id)),
    );
    assert!(!close);
    assert!(matches!(
        resumed.response(),
        BrokerResponse::AccessRequest(BrokerAccessResponse::Resume(receipt))
            if receipt.approval_request_id() == approval_request_id
                && receipt.status() == ApprovalStatus::Pending
    ));

    let (waited, close) = dispatch(
        &mut connection,
        BrokerRequest::AccessRequest(
            BrokerAccessRequest::wait(approval_request_id, Duration::from_millis(1))
                .expect("bounded wait"),
        ),
    );
    assert!(!close);
    assert!(matches!(
        waited.response(),
        BrokerResponse::AccessRequest(BrokerAccessResponse::Wait(wait))
            if wait.receipt().approval_request_id() == approval_request_id
                && wait.receipt().status() == ApprovalStatus::Pending
                && wait.timed_out()
    ));

    let foreign_consumer = Consumer::new(
        [0x6d; 32],
        "Foreign adapter".to_owned(),
        ObservedConsumerIdentity::default(),
        timestamp(710),
    )
    .expect("foreign Consumer");
    runtime
        .device_state()
        .insert_consumer(&foreign_consumer)
        .expect("insert foreign Consumer");
    let foreign_approval_id = runtime
        .request_exact_access(AuthorizationTarget::new(
            foreign_consumer.consumer_id(),
            field_scope,
            Capability::v1(CapabilityName::HttpRequest),
        ))
        .expect("foreign access request")
        .receipt()
        .approval_request_id();
    let (foreign_status, close) = dispatch(
        &mut connection,
        BrokerRequest::AccessRequest(BrokerAccessRequest::status(foreign_approval_id)),
    );
    assert!(!close);
    let (absent_status, close) = dispatch(
        &mut connection,
        BrokerRequest::AccessRequest(BrokerAccessRequest::status(
            crate::ApprovalRequestId::generate(),
        )),
    );
    assert!(!close);
    assert_eq!(foreign_status.response(), absent_status.response());
    assert!(matches!(
        foreign_status.response(),
        BrokerResponse::Error(error) if error.error_code() == BrokerErrorCode::AccessDenied
    ));

    let (replay, close) = dispatch(
        &mut connection,
        BrokerRequest::AuthenticationComplete(proof_request),
    );
    assert!(!close);
    assert_eq!(
        replay.response(),
        &BrokerResponse::Error(crate::BrokerProtocolError::new(
            BrokerErrorCode::InvalidRequest,
            false,
            None,
            None,
        ))
    );
    assert!(runtime
        .device_state()
        .access_rules_for_consumer(consumer_id)
        .expect("rules")
        .is_empty());
    assert!(runtime
        .device_state()
        .use_grants_for_consumer(consumer_id)
        .expect("grants")
        .is_empty());
}

#[test]
fn machine_pause_precedes_rule_evaluation_but_not_human_rule_configuration() {
    let home = TestHome::new("access-rule-pause");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    let consumer = Consumer::new(
        [0x71; 32],
        "Paused rule Consumer".to_owned(),
        ObservedConsumerIdentity::default(),
        timestamp(110),
    )
    .expect("Consumer");
    state.insert_consumer(&consumer).expect("insert Consumer");
    drop(state);

    let runtime = BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store).expect("runtime");
    runtime
        .set_machine_access_paused(true, timestamp(200))
        .expect("pause");
    let target = AuthorizationTarget::new(
        consumer.consumer_id(),
        CredentialFieldScope::new(
            VaultId::generate(),
            CredentialId::generate(),
            SecretFieldId::generate(),
        ),
        Capability::v1(CapabilityName::HttpRequest),
    );
    let approval = BrokerAccessRuleApproval::after_user_approval(
        target,
        SecretFieldKind::ApiToken,
        ConfirmationPolicy::AutomaticWhileUnlocked,
        RuleLifetime::Persistent,
        timestamp(210),
    )
    .expect("approval");
    let creation = runtime
        .create_access_rule(approval)
        .expect("human configuration remains available");
    assert!(creation.newly_created());
    assert!(runtime
        .device_state()
        .use_grants_for_consumer(consumer.consumer_id())
        .expect("grants")
        .is_empty());

    assert!(matches!(
        runtime.evaluate_access_rule(target, SecretFieldKind::ApiToken, timestamp(220)),
        Err(BrokerRuntimeError::MachineAccess(
            BrokerMachineAccessError::Paused
        ))
    ));
    runtime
        .set_machine_access_paused(false, timestamp(230))
        .expect("resume");
    assert!(matches!(
        runtime
            .evaluate_access_rule(target, SecretFieldKind::ApiToken, timestamp(240))
            .expect("evaluate"),
        BrokerAccessRuleEvaluation::MatchingRule(_)
    ));
}

#[test]
fn runtime_grants_are_paused_consumer_bound_and_unlock_session_bound() {
    let home = TestHome::new("use-grant-runtime");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    let consumer = Consumer::new(
        [0x72; 32],
        "Grant integration Consumer".to_owned(),
        ObservedConsumerIdentity::default(),
        timestamp(110),
    )
    .expect("Consumer");
    state.insert_consumer(&consumer).expect("insert Consumer");
    drop(state);

    let vault = home.create_vault("Grant");
    let mut runtime =
        BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store).expect("runtime");
    runtime
        .process()
        .vault_sessions()
        .open_vault(&vault.path)
        .expect("open vault");
    let unlocked = runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password.clone())
        .expect("unlock");
    let first_session = unlocked.vault_session_id().expect("session");
    let target = AuthorizationTarget::new(
        consumer.consumer_id(),
        CredentialFieldScope::new(
            vault.vault_id,
            CredentialId::generate(),
            SecretFieldId::generate(),
        ),
        Capability::v1(CapabilityName::HttpRequest),
    );
    runtime
        .create_access_rule(
            BrokerAccessRuleApproval::after_user_approval(
                target,
                SecretFieldKind::ApiToken,
                ConfirmationPolicy::AutomaticWhileUnlocked,
                RuleLifetime::Persistent,
                timestamp(200),
            )
            .expect("rule approval"),
        )
        .expect("rule");
    runtime
        .set_machine_access_paused(true, timestamp(210))
        .expect("pause");

    assert!(matches!(
        runtime.issue_automatic_rule_grant(
            target,
            SecretFieldKind::ApiToken,
            first_session,
            timestamp(220),
            timestamp(500),
        ),
        Err(BrokerRuntimeError::MachineAccess(
            BrokerMachineAccessError::Paused
        ))
    ));
    assert!(runtime
        .device_state()
        .use_grants_for_consumer(consumer.consumer_id())
        .expect("grants")
        .is_empty());

    let allow_once = runtime
        .issue_allow_once_grant(
            BrokerAllowOnceApproval::after_user_approval(
                target,
                SecretFieldKind::ApiToken,
                first_session,
                timestamp(221),
                timestamp(500),
            )
            .expect("Allow Once approval"),
        )
        .expect("human approval remains available");
    assert_eq!(allow_once.basis(), BrokerUseGrantBasis::AllowOnce);
    let allow_once_id = allow_once.grant().use_grant_id();
    assert!(matches!(
        runtime.authorize_use_grant(
            allow_once_id,
            target,
            SecretFieldKind::ApiToken,
            first_session,
            timestamp(230),
        ),
        Err(BrokerRuntimeError::MachineAccess(
            BrokerMachineAccessError::Paused
        ))
    ));
    assert_eq!(
        runtime
            .device_state()
            .use_grants_for_consumer(consumer.consumer_id())
            .expect("paused grant")
            .len(),
        1
    );

    runtime
        .set_machine_access_paused(false, timestamp(240))
        .expect("resume");
    assert!(runtime
        .authorize_use_grant(
            allow_once_id,
            target,
            SecretFieldKind::ApiToken,
            first_session,
            timestamp(250),
        )
        .expect("consume Allow Once")
        .consumed());
    let automatic = runtime
        .issue_automatic_rule_grant(
            target,
            SecretFieldKind::ApiToken,
            first_session,
            timestamp(260),
            timestamp(500),
        )
        .expect("automatic grant");
    assert_eq!(
        automatic.basis(),
        BrokerUseGrantBasis::AutomaticWhileUnlocked
    );

    runtime
        .process()
        .vault_sessions()
        .lock_vault(vault.vault_id)
        .expect("lock")
        .expect("lock event");
    let second_session = runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password)
        .expect("unlock again")
        .vault_session_id()
        .expect("second session");
    assert_ne!(first_session, second_session);
    assert!(matches!(
        runtime.authorize_use_grant(
            automatic.grant().use_grant_id(),
            target,
            SecretFieldKind::ApiToken,
            first_session,
            timestamp(270),
        ),
        Err(BrokerRuntimeError::UseGrant(
            BrokerUseGrantError::GrantExpired
        ))
    ));
    let replacement = runtime
        .issue_automatic_rule_grant(
            target,
            SecretFieldKind::ApiToken,
            second_session,
            timestamp(280),
            timestamp(500),
        )
        .expect("new-session grant");
    assert_ne!(
        replacement.grant().use_grant_id(),
        automatic.grant().use_grant_id()
    );
    runtime.shutdown().expect("shutdown");
}

#[test]
fn explicit_outbound_operations_are_attributed_before_and_after_execution() {
    let home = TestHome::new("outbound-operation-audit");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    let private_label = "KN_TEMPLATE_ENDPOINT_64_72D1";
    let consumer = Consumer::new(
        [0x74; 32],
        private_label.to_owned(),
        ObservedConsumerIdentity::default(),
        timestamp(110),
    )
    .expect("Consumer");
    state.insert_consumer(&consumer).expect("insert Consumer");
    drop(state);

    let vault = home.create_vault("OutboundOperation");
    let mut runtime =
        BrokerRuntime::reopen_with_paths_at(home.paths.clone(), key_store, timestamp(120))
            .expect("runtime");
    runtime
        .process()
        .vault_sessions()
        .open_vault(&vault.path)
        .expect("open vault");
    let vault_session_id = runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password.clone())
        .expect("unlock")
        .vault_session_id()
        .expect("session");

    let http_target = AuthorizationTarget::new(
        consumer.consumer_id(),
        CredentialFieldScope::new(
            vault.vault_id,
            CredentialId::generate(),
            SecretFieldId::generate(),
        ),
        Capability::v1(CapabilityName::HttpRequest),
    );
    let http_grant = runtime
        .issue_allow_once_grant(
            BrokerAllowOnceApproval::after_user_approval(
                http_target,
                SecretFieldKind::ApiToken,
                vault_session_id,
                timestamp(200),
                timestamp(500),
            )
            .expect("HTTP approval"),
        )
        .expect("HTTP grant");
    let http_grant_id = http_grant.grant().use_grant_id();
    let http_authorization = runtime
        .begin_outbound_credential_operation_at(
            http_grant_id,
            http_target,
            SecretFieldKind::ApiToken,
            vault_session_id,
            timestamp(210),
        )
        .expect("begin HTTP");
    let http_pending_id = http_authorization.authorization_event_id();
    assert_eq!(http_authorization.consumer_id(), consumer.consumer_id());
    assert_eq!(http_authorization.field_scope(), http_target.field_scope());
    assert_eq!(http_authorization.capability(), http_target.capability());
    assert_eq!(http_authorization.use_grant_id(), http_grant_id);
    assert!(!format!("{http_authorization:?}").contains(private_label));
    let http_outcome_id = runtime
        .finish_outbound_credential_operation_at(
            http_authorization,
            BrokerOutboundOperationOutcome::Succeeded,
            timestamp(220),
        )
        .expect("finish HTTP");

    let process_target = AuthorizationTarget::new(
        consumer.consumer_id(),
        CredentialFieldScope::new(
            vault.vault_id,
            CredentialId::generate(),
            SecretFieldId::generate(),
        ),
        Capability::v1(CapabilityName::ProcessRun),
    );
    let process_grant = runtime
        .issue_allow_once_grant(
            BrokerAllowOnceApproval::after_user_approval(
                process_target,
                SecretFieldKind::GenericSecret,
                vault_session_id,
                timestamp(230),
                timestamp(500),
            )
            .expect("process approval"),
        )
        .expect("process grant");
    let process_grant_id = process_grant.grant().use_grant_id();
    let process_authorization = runtime
        .begin_outbound_credential_operation_at(
            process_grant_id,
            process_target,
            SecretFieldKind::GenericSecret,
            vault_session_id,
            timestamp(240),
        )
        .expect("begin process");
    let process_pending_id = process_authorization.authorization_event_id();
    let process_outcome_id = runtime
        .finish_outbound_credential_operation_at(
            process_authorization,
            BrokerOutboundOperationOutcome::Failed,
            timestamp(250),
        )
        .expect("finish process");

    let paused_grant = runtime
        .issue_allow_once_grant(
            BrokerAllowOnceApproval::after_user_approval(
                http_target,
                SecretFieldKind::ApiToken,
                vault_session_id,
                timestamp(260),
                timestamp(500),
            )
            .expect("paused approval"),
        )
        .expect("paused grant");
    let paused_grant_id = paused_grant.grant().use_grant_id();
    runtime
        .set_machine_access_paused(true, timestamp(270))
        .expect("pause");
    assert!(matches!(
        runtime.begin_outbound_credential_operation_at(
            paused_grant_id,
            http_target,
            SecretFieldKind::ApiToken,
            vault_session_id,
            timestamp(280),
        ),
        Err(BrokerRuntimeError::MachineAccess(
            BrokerMachineAccessError::Paused
        ))
    ));
    runtime
        .set_machine_access_paused(false, timestamp(290))
        .expect("resume");
    let denied_grant_id = UseGrantId::generate();
    assert!(matches!(
        runtime.begin_outbound_credential_operation_at(
            denied_grant_id,
            http_target,
            SecretFieldKind::ApiToken,
            vault_session_id,
            timestamp(295),
        ),
        Err(BrokerRuntimeError::UseGrant(
            BrokerUseGrantError::AccessDenied
        ))
    ));

    let metadata_target = AuthorizationTarget::new(
        consumer.consumer_id(),
        CredentialFieldScope::new(
            vault.vault_id,
            CredentialId::generate(),
            SecretFieldId::generate(),
        ),
        Capability::v1(CapabilityName::CredentialSearch),
    );
    let metadata_grant = runtime
        .issue_allow_once_grant(
            BrokerAllowOnceApproval::after_user_approval(
                metadata_target,
                SecretFieldKind::Password,
                vault_session_id,
                timestamp(300),
                timestamp(500),
            )
            .expect("metadata approval"),
        )
        .expect("metadata grant");
    let metadata_grant_id = metadata_grant.grant().use_grant_id();
    assert!(matches!(
        runtime.begin_outbound_credential_operation_at(
            metadata_grant_id,
            metadata_target,
            SecretFieldKind::Password,
            vault_session_id,
            timestamp(310),
        ),
        Err(BrokerRuntimeError::OutboundOperation(
            BrokerOutboundOperationError::UnsupportedCapability
        ))
    ));

    let events = runtime
        .device_state()
        .recent_audit_events(10)
        .expect("audit events");
    assert_eq!(events.len(), 6);
    let expected = [
        (
            timestamp(295),
            http_target,
            denied_grant_id,
            AuditDecision::Denied,
            ConfirmationMethod::None,
            None,
        ),
        (
            timestamp(280),
            http_target,
            paused_grant_id,
            AuditDecision::Paused,
            ConfirmationMethod::None,
            None,
        ),
        (
            timestamp(250),
            process_target,
            process_grant_id,
            AuditDecision::Failed,
            ConfirmationMethod::UserApproval,
            Some(process_outcome_id),
        ),
        (
            timestamp(240),
            process_target,
            process_grant_id,
            AuditDecision::Pending,
            ConfirmationMethod::UserApproval,
            Some(process_pending_id),
        ),
        (
            timestamp(220),
            http_target,
            http_grant_id,
            AuditDecision::Allowed,
            ConfirmationMethod::UserApproval,
            Some(http_outcome_id),
        ),
        (
            timestamp(210),
            http_target,
            http_grant_id,
            AuditDecision::Pending,
            ConfirmationMethod::UserApproval,
            Some(http_pending_id),
        ),
    ];
    for (event, (occurred_at, target, grant_id, decision, confirmation, event_id)) in
        events.iter().zip(expected)
    {
        assert_eq!(event.occurred_at(), occurred_at);
        assert_eq!(event.kind(), AuditEventKind::CredentialUse);
        assert_eq!(event.scope().consumer_id(), Some(target.consumer_id()));
        assert_eq!(event.scope().field_scope(), Some(target.field_scope()));
        assert_eq!(event.scope().capability(), Some(target.capability()));
        assert_eq!(event.scope().use_grant_id(), Some(grant_id));
        assert_eq!(event.decision(), decision);
        assert_eq!(event.confirmation_method(), confirmation);
        if let Some(event_id) = event_id {
            assert_eq!(event.audit_event_id(), event_id);
        }
    }
    assert!(runtime
        .device_state()
        .use_grants_for_consumer(consumer.consumer_id())
        .expect("remaining grants")
        .iter()
        .any(|grant| grant.use_grant_id() == metadata_grant_id));
    runtime.shutdown_at(timestamp(320)).expect("shutdown");
}

#[test]
fn brokered_http_request_places_one_exact_secret_and_sanitizes_results() {
    const SECRET_MARKER: &str = "KN_HTTP_RUNTIME_SECRET_85";
    const URL_MARKER: &str = "https://api.example.test/v1/releases";
    const REQUEST_BODY_MARKER: &str = "{\"name\":\"preview\"}";

    let home = TestHome::new("http-request-runtime");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    let consumer = Consumer::new(
        [0x85; 32],
        "HTTP integration Consumer".to_owned(),
        ObservedConsumerIdentity::default(),
        timestamp(110),
    )
    .expect("Consumer");
    state.insert_consumer(&consumer).expect("insert Consumer");
    let other_consumer = Consumer::new(
        [0x86; 32],
        "Other HTTP Consumer".to_owned(),
        ObservedConsumerIdentity::default(),
        timestamp(111),
    )
    .expect("other Consumer");
    state
        .insert_consumer(&other_consumer)
        .expect("insert other Consumer");
    drop(state);

    let vault = home.create_vault("HttpRequest");
    let mut unlocked = VaultCore::new()
        .open_vault(OpenVaultRequest {
            path: vault.path.clone(),
        })
        .expect("open fixture")
        .unlock(UnlockRequest {
            master_password: vault.password.clone(),
        })
        .expect("unlock fixture");
    let created = unlocked
        .create_credential(CredentialDraft {
            title: "Release API token".to_owned(),
            template_id: Some("api-token".to_owned()),
            fields: vec![CredentialField::secret(
                "token",
                SecretFieldKind::ApiToken,
                SecretBytes::new(SECRET_MARKER.as_bytes().to_vec()),
            )],
            tags: Vec::new(),
            favorite: false,
        })
        .expect("create token");
    let credential_id = created.credential.credential_id;
    let secret_field_id = created.credential.secret_fields[0].secret_field_id;
    drop(unlocked.lock());

    let mut runtime =
        BrokerRuntime::reopen_with_paths_at(home.paths.clone(), key_store, timestamp(120))
            .expect("runtime");
    runtime
        .process()
        .vault_sessions()
        .open_vault(&vault.path)
        .expect("open vault");
    let vault_session_id = runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password)
        .expect("unlock")
        .vault_session_id()
        .expect("session");
    let capability = Capability::v1(CapabilityName::HttpRequest);
    let profile = runtime
        .create_usage_profile(
            consumer.consumer_id(),
            "Bearer API".to_owned(),
            UsageProfileDefinition::new(capability, UsagePlacement::HttpBearerAuthorization {})
                .expect("definition"),
        )
        .expect("profile");
    let other_profile = runtime
        .create_usage_profile(
            other_consumer.consumer_id(),
            "Other Bearer API".to_owned(),
            UsageProfileDefinition::new(capability, UsagePlacement::HttpBearerAuthorization {})
                .expect("other definition"),
        )
        .expect("other profile");
    let incompatible_profile = runtime
        .create_usage_profile(
            consumer.consumer_id(),
            "Child environment".to_owned(),
            UsageProfileDefinition::new(
                Capability::v1(CapabilityName::ProcessRun),
                UsagePlacement::ProcessEnvironment {
                    variable_name: "SERVICE_TOKEN".to_owned(),
                },
            )
            .expect("incompatible definition"),
        )
        .expect("incompatible profile");
    let target = AuthorizationTarget::new(
        consumer.consumer_id(),
        CredentialFieldScope::new(vault.vault_id, credential_id, secret_field_id),
        capability,
    );
    let grant = runtime
        .issue_allow_once_grant(
            BrokerAllowOnceApproval::after_user_approval(
                target,
                SecretFieldKind::ApiToken,
                vault_session_id,
                timestamp(200),
                timestamp(500),
            )
            .expect("approval"),
        )
        .expect("grant");
    let response_body = format!("{{\"echo\":\"{SECRET_MARKER}\"}}").into_bytes();
    let transport = ExpectedHttpTransport::succeeding(
        URL_MARKER,
        "Authorization",
        &format!("Bearer {SECRET_MARKER}"),
        REQUEST_BODY_MARKER.as_bytes(),
        response_body,
    );
    runtime
        .set_machine_access_paused(true, timestamp(202))
        .expect("pause HTTP");
    let error = runtime
        .execute_http_request_with_transport_at(
            grant.grant().use_grant_id(),
            target,
            SecretFieldKind::ApiToken,
            vault_session_id,
            other_profile.usage_profile_id(),
            BrokerHttpRequest::new(
                BrokerHttpMethod::Post,
                URL_MARKER.to_owned(),
                Vec::new(),
                REQUEST_BODY_MARKER.as_bytes().to_vec(),
            )
            .expect("paused request"),
            &transport,
            timestamp(203),
            timestamp(204),
        )
        .expect_err("paused before profile lookup");
    assert!(matches!(
        error,
        BrokerRuntimeError::MachineAccess(BrokerMachineAccessError::Paused)
    ));
    assert!(transport.response.lock().expect("HTTP response").is_some());
    runtime
        .set_machine_access_paused(false, timestamp(204))
        .expect("resume HTTP");
    for (usage_profile_id, expects_capability_mismatch) in [
        (other_profile.usage_profile_id(), false),
        (incompatible_profile.usage_profile_id(), true),
    ] {
        let error = runtime
            .execute_http_request_with_transport_at(
                grant.grant().use_grant_id(),
                target,
                SecretFieldKind::ApiToken,
                vault_session_id,
                usage_profile_id,
                BrokerHttpRequest::new(
                    BrokerHttpMethod::Post,
                    URL_MARKER.to_owned(),
                    Vec::new(),
                    REQUEST_BODY_MARKER.as_bytes().to_vec(),
                )
                .expect("preflight request"),
                &transport,
                timestamp(205),
                timestamp(206),
            )
            .expect_err("profile preflight");
        let matches_expected = if expects_capability_mismatch {
            matches!(
                error,
                BrokerRuntimeError::UsageProfile(BrokerUsageProfileError::CapabilityMismatch)
            )
        } else {
            matches!(
                error,
                BrokerRuntimeError::UsageProfile(BrokerUsageProfileError::ProfileUnavailable)
            )
        };
        assert!(matches_expected);
        assert!(transport.response.lock().expect("HTTP response").is_some());
    }
    assert!(runtime
        .device_state()
        .use_grants_for_consumer(consumer.consumer_id())
        .expect("unconsumed preflight grant")
        .iter()
        .any(|candidate| candidate.use_grant_id() == grant.grant().use_grant_id()));
    let response = runtime
        .execute_http_request_with_transport_at(
            grant.grant().use_grant_id(),
            target,
            SecretFieldKind::ApiToken,
            vault_session_id,
            profile.usage_profile_id(),
            BrokerHttpRequest::new(
                BrokerHttpMethod::Post,
                URL_MARKER.to_owned(),
                vec![BrokerHttpHeader::new(
                    "Content-Type".to_owned(),
                    "application/json".to_owned(),
                )
                .expect("header")],
                REQUEST_BODY_MARKER.as_bytes().to_vec(),
            )
            .expect("request"),
            &transport,
            timestamp(210),
            timestamp(220),
        )
        .expect("HTTP response");
    assert_eq!(response.status_code(), 201);
    assert_eq!(response.body(), b"{\"echo\":\"[REDACTED]\"}");
    assert!(!response.truncated());

    let failed_grant = runtime
        .issue_allow_once_grant(
            BrokerAllowOnceApproval::after_user_approval(
                target,
                SecretFieldKind::ApiToken,
                vault_session_id,
                timestamp(230),
                timestamp(500),
            )
            .expect("failure approval"),
        )
        .expect("failure grant");
    let failing_transport = ExpectedHttpTransport::failing(
        URL_MARKER,
        "Authorization",
        &format!("Bearer {SECRET_MARKER}"),
        REQUEST_BODY_MARKER.as_bytes(),
    );
    let error = runtime
        .execute_http_request_with_transport_at(
            failed_grant.grant().use_grant_id(),
            target,
            SecretFieldKind::ApiToken,
            vault_session_id,
            profile.usage_profile_id(),
            BrokerHttpRequest::new(
                BrokerHttpMethod::Post,
                URL_MARKER.to_owned(),
                Vec::new(),
                REQUEST_BODY_MARKER.as_bytes().to_vec(),
            )
            .expect("failure request"),
            &failing_transport,
            timestamp(240),
            timestamp(250),
        )
        .expect_err("network failure");
    assert!(matches!(
        error,
        BrokerRuntimeError::HttpRequest(BrokerHttpRequestError::NetworkOperationFailed)
    ));
    let rendered_error = error.to_string();
    assert!(!rendered_error.contains(SECRET_MARKER));
    assert!(!rendered_error.contains(URL_MARKER));
    assert!(!rendered_error.contains(REQUEST_BODY_MARKER));

    let kind_mismatch_grant = runtime
        .issue_allow_once_grant(
            BrokerAllowOnceApproval::after_user_approval(
                target,
                SecretFieldKind::Password,
                vault_session_id,
                timestamp(260),
                timestamp(500),
            )
            .expect("kind mismatch approval"),
        )
        .expect("kind mismatch grant");
    let unused_transport = ExpectedHttpTransport::failing(
        URL_MARKER,
        "Authorization",
        &format!("Bearer {SECRET_MARKER}"),
        REQUEST_BODY_MARKER.as_bytes(),
    );
    let error = runtime
        .execute_http_request_with_transport_at(
            kind_mismatch_grant.grant().use_grant_id(),
            target,
            SecretFieldKind::Password,
            vault_session_id,
            profile.usage_profile_id(),
            BrokerHttpRequest::new(
                BrokerHttpMethod::Post,
                URL_MARKER.to_owned(),
                Vec::new(),
                REQUEST_BODY_MARKER.as_bytes().to_vec(),
            )
            .expect("kind mismatch request"),
            &unused_transport,
            timestamp(260),
            timestamp(270),
        )
        .expect_err("changed field kind");
    assert!(matches!(
        error,
        BrokerRuntimeError::HttpRequest(BrokerHttpRequestError::SecretUnavailable)
    ));
    assert!(unused_transport
        .response
        .lock()
        .expect("unused HTTP response")
        .is_some());

    let events = runtime
        .device_state()
        .recent_audit_events(10)
        .expect("audit");
    assert_eq!(events.len(), 7);
    assert_eq!(
        events
            .iter()
            .map(|event| (event.occurred_at(), event.decision()))
            .collect::<Vec<_>>(),
        vec![
            (timestamp(270), AuditDecision::Failed),
            (timestamp(260), AuditDecision::Pending),
            (timestamp(250), AuditDecision::Failed),
            (timestamp(240), AuditDecision::Pending),
            (timestamp(220), AuditDecision::Allowed),
            (timestamp(210), AuditDecision::Pending),
            (timestamp(203), AuditDecision::Paused),
        ]
    );
    for event in &events {
        assert_eq!(event.kind(), AuditEventKind::CredentialUse);
        assert_eq!(event.scope().consumer_id(), Some(consumer.consumer_id()));
        assert_eq!(event.scope().field_scope(), Some(target.field_scope()));
        assert_eq!(event.scope().capability(), Some(capability));
    }
    let audit = runtime
        .export_audit_json_at(BrokerAuditFilter::all(), timestamp(300))
        .expect("audit export");
    let audit_json = audit.as_str();
    for marker in [SECRET_MARKER, URL_MARKER, REQUEST_BODY_MARKER, "Bearer "] {
        assert!(!audit_json.contains(marker), "{marker}");
    }
    runtime.shutdown_at(timestamp(310)).expect("shutdown");
}

#[test]
fn brokered_process_run_places_one_exact_secret_and_sanitizes_results() {
    const SECRET_MARKER: &str = "KN_PROCESS_RUNTIME_SECRET_86";
    const ENVIRONMENT_NAME_MARKER: &str = "KN_PROCESS_AUDIT_NAME_86";
    const ENVIRONMENT_VALUE_MARKER: &str = "KN_PROCESS_AUDIT_VALUE_86";

    let home = TestHome::new("process-run-runtime");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    let consumer = Consumer::new(
        [0x87; 32],
        "Process integration Consumer".to_owned(),
        ObservedConsumerIdentity::default(),
        timestamp(110),
    )
    .expect("Consumer");
    state.insert_consumer(&consumer).expect("insert Consumer");
    drop(state);

    let vault = home.create_vault("ProcessRun");
    let mut unlocked = VaultCore::new()
        .open_vault(OpenVaultRequest {
            path: vault.path.clone(),
        })
        .expect("open fixture")
        .unlock(UnlockRequest {
            master_password: vault.password.clone(),
        })
        .expect("unlock fixture");
    let created = unlocked
        .create_credential(CredentialDraft {
            title: "CLI token".to_owned(),
            template_id: Some("api-token".to_owned()),
            fields: vec![CredentialField::secret(
                "token",
                SecretFieldKind::GenericSecret,
                SecretBytes::new(SECRET_MARKER.as_bytes().to_vec()),
            )],
            tags: Vec::new(),
            favorite: false,
        })
        .expect("create token");
    let credential_id = created.credential.credential_id;
    let secret_field_id = created.credential.secret_fields[0].secret_field_id;
    drop(unlocked.lock());

    let mut runtime =
        BrokerRuntime::reopen_with_paths_at(home.paths.clone(), key_store, timestamp(120))
            .expect("runtime");
    runtime
        .process()
        .vault_sessions()
        .open_vault(&vault.path)
        .expect("open vault");
    let vault_session_id = runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password)
        .expect("unlock")
        .vault_session_id()
        .expect("session");
    let capability = Capability::v1(CapabilityName::ProcessRun);
    let profile = runtime
        .create_usage_profile(
            consumer.consumer_id(),
            "Secret stdin".to_owned(),
            UsageProfileDefinition::new(
                capability,
                UsagePlacement::ProcessStdin {
                    append_newline: true,
                },
            )
            .expect("definition"),
        )
        .expect("profile");
    let incompatible_profile = runtime
        .create_usage_profile(
            consumer.consumer_id(),
            "HTTP header".to_owned(),
            UsageProfileDefinition::new(
                Capability::v1(CapabilityName::HttpRequest),
                UsagePlacement::HttpBearerAuthorization {},
            )
            .expect("incompatible definition"),
        )
        .expect("incompatible profile");
    let target = AuthorizationTarget::new(
        consumer.consumer_id(),
        CredentialFieldScope::new(vault.vault_id, credential_id, secret_field_id),
        capability,
    );
    let grant = runtime
        .issue_allow_once_grant(
            BrokerAllowOnceApproval::after_user_approval(
                target,
                SecretFieldKind::GenericSecret,
                vault_session_id,
                timestamp(200),
                timestamp(500),
            )
            .expect("approval"),
        )
        .expect("grant");
    let process_request = || {
        BrokerProcessRunRequest::new(
            "/bin/cat".to_owned(),
            Vec::new(),
            None,
            vec![BrokerProcessEnvironment::new(
                ENVIRONMENT_NAME_MARKER.to_owned(),
                ENVIRONMENT_VALUE_MARKER.to_owned(),
            )
            .expect("environment")],
            Duration::from_secs(2),
        )
        .expect("request")
    };

    let error = runtime
        .execute_process_run_with_timestamps(
            grant.grant().use_grant_id(),
            target,
            SecretFieldKind::GenericSecret,
            vault_session_id,
            incompatible_profile.usage_profile_id(),
            process_request(),
            &BrokerProcessRunCancellation::default(),
            timestamp(205),
            timestamp(206),
        )
        .expect_err("profile preflight");
    assert!(matches!(
        error,
        BrokerRuntimeError::UsageProfile(BrokerUsageProfileError::CapabilityMismatch)
    ));
    assert!(runtime
        .device_state()
        .use_grants_for_consumer(consumer.consumer_id())
        .expect("unconsumed preflight grant")
        .iter()
        .any(|candidate| candidate.use_grant_id() == grant.grant().use_grant_id()));

    let response = runtime
        .execute_process_run_with_timestamps(
            grant.grant().use_grant_id(),
            target,
            SecretFieldKind::GenericSecret,
            vault_session_id,
            profile.usage_profile_id(),
            process_request(),
            &BrokerProcessRunCancellation::default(),
            timestamp(210),
            timestamp(220),
        )
        .expect("process response");
    assert_eq!(response.exit_code(), Some(0));
    assert!(!response.terminated_by_signal());
    assert_eq!(response.stdout(), b"[REDACTED]\n");
    assert!(response.stderr().is_empty());
    assert!(!response.stdout_truncated());
    assert!(!response.stderr_truncated());

    let cancelled_grant = runtime
        .issue_allow_once_grant(
            BrokerAllowOnceApproval::after_user_approval(
                target,
                SecretFieldKind::GenericSecret,
                vault_session_id,
                timestamp(225),
                timestamp(500),
            )
            .expect("cancel approval"),
        )
        .expect("cancel grant");
    let cancellation = BrokerProcessRunCancellation::default();
    cancellation.cancel();
    let error = runtime
        .execute_process_run_with_timestamps(
            cancelled_grant.grant().use_grant_id(),
            target,
            SecretFieldKind::GenericSecret,
            vault_session_id,
            profile.usage_profile_id(),
            process_request(),
            &cancellation,
            timestamp(230),
            timestamp(240),
        )
        .expect_err("cancelled operation");
    assert!(matches!(
        error,
        BrokerRuntimeError::ProcessRun(BrokerProcessRunError::Cancelled)
    ));

    let nonzero_grant = runtime
        .issue_allow_once_grant(
            BrokerAllowOnceApproval::after_user_approval(
                target,
                SecretFieldKind::GenericSecret,
                vault_session_id,
                timestamp(245),
                timestamp(500),
            )
            .expect("nonzero approval"),
        )
        .expect("nonzero grant");
    let nonzero_response = runtime
        .execute_process_run_with_timestamps(
            nonzero_grant.grant().use_grant_id(),
            target,
            SecretFieldKind::GenericSecret,
            vault_session_id,
            profile.usage_profile_id(),
            BrokerProcessRunRequest::new(
                "/usr/bin/grep".to_owned(),
                vec!["-F".to_owned(), "KN_PROCESS_NONZERO_NO_MATCH_86".to_owned()],
                None,
                Vec::new(),
                Duration::from_secs(2),
            )
            .expect("nonzero request"),
            &BrokerProcessRunCancellation::default(),
            timestamp(250),
            timestamp(260),
        )
        .expect("nonzero process response");
    assert_ne!(nonzero_response.exit_code(), Some(0));

    let events = runtime
        .device_state()
        .recent_audit_events(10)
        .expect("audit");
    assert_eq!(
        events
            .iter()
            .map(|event| (event.occurred_at(), event.decision()))
            .collect::<Vec<_>>(),
        vec![
            (timestamp(260), AuditDecision::Allowed),
            (timestamp(250), AuditDecision::Pending),
            (timestamp(240), AuditDecision::Failed),
            (timestamp(230), AuditDecision::Pending),
            (timestamp(220), AuditDecision::Allowed),
            (timestamp(210), AuditDecision::Pending),
        ]
    );
    for event in &events {
        assert_eq!(event.kind(), AuditEventKind::CredentialUse);
        assert_eq!(event.scope().consumer_id(), Some(consumer.consumer_id()));
        assert_eq!(event.scope().field_scope(), Some(target.field_scope()));
        assert_eq!(event.scope().capability(), Some(capability));
    }
    let audit = runtime
        .export_audit_json_at(BrokerAuditFilter::all(), timestamp(300))
        .expect("audit export");
    for marker in [
        SECRET_MARKER,
        "/bin/cat",
        "/usr/bin/grep",
        "KN_PROCESS_NONZERO_NO_MATCH_86",
        ENVIRONMENT_NAME_MARKER,
        ENVIRONMENT_VALUE_MARKER,
        "[REDACTED]",
    ] {
        assert!(!audit.as_str().contains(marker), "{marker}");
    }
    runtime.shutdown_at(timestamp(310)).expect("shutdown");
}

#[test]
fn authorized_search_blocks_metadata_enumeration_and_projects_one_granted_field() {
    let home = TestHome::new("credential-search-runtime");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    let consumer = Consumer::new(
        [0x73; 32],
        "Search integration Consumer".to_owned(),
        ObservedConsumerIdentity::default(),
        timestamp(110),
    )
    .expect("Consumer");
    state.insert_consumer(&consumer).expect("insert Consumer");
    drop(state);

    let vault = home.create_vault("Search");
    let mut unlocked = VaultCore::new()
        .open_vault(OpenVaultRequest {
            path: vault.path.clone(),
        })
        .expect("open for fixture")
        .unlock(UnlockRequest {
            master_password: vault.password.clone(),
        })
        .expect("unlock for fixture");
    let authorized = unlocked
        .create_item(VaultItemDraft {
            title: "Production API".to_owned(),
            content: VaultItemContent::Login(LoginItem {
                username: Some("alice-private".to_owned()),
                password: Some(SecretBytes::new(b"authorized-secret".to_vec())),
                urls: vec!["https://private.example.test".to_owned()],
                notes: None,
                totp_secret: Some(SecretBytes::new(b"JBSWY3DPEHPK3PXP".to_vec())),
            }),
            tags: vec!["private-tag".to_owned()],
            favorite: true,
        })
        .expect("authorized credential");
    let unrelated = unlocked
        .create_item(VaultItemDraft {
            title: "Unrelated account".to_owned(),
            content: VaultItemContent::Login(LoginItem {
                username: Some("bob".to_owned()),
                password: Some(SecretBytes::new(b"unrelated-secret".to_vec())),
                urls: vec![],
                notes: None,
                totp_secret: None,
            }),
            tags: vec![],
            favorite: false,
        })
        .expect("unrelated credential");
    let credential_id: CredentialId = authorized.id.0.parse().expect("credential ID");
    let unrelated_id: CredentialId = unrelated.id.0.parse().expect("unrelated ID");
    let fixture_summary = unlocked
        .credential_summary(credential_id)
        .expect("summary")
        .expect("active");
    let unrelated_summary = unlocked
        .credential_summary(unrelated_id)
        .expect("unrelated summary")
        .expect("unrelated active");
    let password_field = fixture_summary
        .secret_fields
        .iter()
        .find(|field| field.kind == SecretFieldKind::Password)
        .expect("password field");
    let totp_field = fixture_summary
        .secret_fields
        .iter()
        .find(|field| field.kind == SecretFieldKind::TotpSeed)
        .expect("TOTP field");
    let password_field_id = password_field.secret_field_id;
    let totp_field_id = totp_field.secret_field_id;
    let unrelated_password_field_id = unrelated_summary
        .secret_fields
        .iter()
        .find(|field| field.kind == SecretFieldKind::Password)
        .expect("unrelated password field")
        .secret_field_id;
    drop(unlocked.lock());

    let mut runtime =
        BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store).expect("runtime");
    runtime
        .process()
        .vault_sessions()
        .open_vault(&vault.path)
        .expect("open vault");
    let vault_session_id = runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password.clone())
        .expect("unlock vault")
        .vault_session_id()
        .expect("session");
    let target = AuthorizationTarget::new(
        consumer.consumer_id(),
        CredentialFieldScope::new(vault.vault_id, credential_id, password_field_id),
        Capability::v1(CapabilityName::CredentialSearch),
    );
    runtime
        .create_access_rule(
            BrokerAccessRuleApproval::after_user_approval(
                target,
                SecretFieldKind::Password,
                ConfirmationPolicy::AutomaticWhileUnlocked,
                RuleLifetime::Persistent,
                timestamp(200),
            )
            .expect("rule approval"),
        )
        .expect("rule");
    let grant = runtime
        .issue_automatic_rule_grant(
            target,
            SecretFieldKind::Password,
            vault_session_id,
            timestamp(210),
            timestamp(500),
        )
        .expect("search grant");

    let found_result = runtime
        .search_authorized_credential(
            grant.grant().use_grant_id(),
            target,
            SecretFieldKind::Password,
            vault_session_id,
            timestamp(220),
            BrokerCredentialSearchQuery::new("production".to_owned()).expect("query"),
        )
        .expect("search");
    let found = found_result.credential().expect("match");
    assert_eq!(found.credential_id(), credential_id);
    assert_eq!(found.title(), "Production API");
    assert_eq!(
        found.authorized_field().secret_field_id(),
        password_field_id
    );
    assert_eq!(found.authorized_field().kind(), SecretFieldKind::Password);
    assert_ne!(found.authorized_field().secret_field_id(), totp_field_id);

    for omitted_metadata in [
        "unrelated account",
        "alice-private",
        "private.example",
        "private-tag",
    ] {
        let result = runtime
            .search_authorized_credential(
                grant.grant().use_grant_id(),
                target,
                SecretFieldKind::Password,
                vault_session_id,
                timestamp(221),
                BrokerCredentialSearchQuery::new(omitted_metadata.to_owned()).expect("query"),
            )
            .expect("bounded search");
        assert!(result.credential().is_none(), "{omitted_metadata}");
    }

    let unauthorized_targets = [
        AuthorizationTarget::new(
            consumer.consumer_id(),
            CredentialFieldScope::new(vault.vault_id, unrelated_id, unrelated_password_field_id),
            Capability::v1(CapabilityName::CredentialSearch),
        ),
        AuthorizationTarget::new(
            consumer.consumer_id(),
            CredentialFieldScope::new(vault.vault_id, credential_id, totp_field_id),
            Capability::v1(CapabilityName::CredentialSearch),
        ),
        AuthorizationTarget::new(
            consumer.consumer_id(),
            CredentialFieldScope::new(
                vault.vault_id,
                CredentialId::generate(),
                SecretFieldId::generate(),
            ),
            Capability::v1(CapabilityName::CredentialSearch),
        ),
        AuthorizationTarget::new(
            consumer.consumer_id(),
            CredentialFieldScope::new(
                VaultId::generate(),
                CredentialId::generate(),
                SecretFieldId::generate(),
            ),
            Capability::v1(CapabilityName::CredentialSearch),
        ),
    ];
    assert!(matches!(
        runtime.issue_automatic_rule_grant(
            unauthorized_targets[3],
            SecretFieldKind::Password,
            vault_session_id,
            timestamp(222),
            timestamp(500),
        ),
        Err(BrokerRuntimeError::UseGrant(
            BrokerUseGrantError::AccessDenied
        ))
    ));
    let mut denial_text = None;
    for unauthorized_target in unauthorized_targets {
        let error = runtime
            .search_authorized_credential(
                grant.grant().use_grant_id(),
                unauthorized_target,
                SecretFieldKind::Password,
                vault_session_id,
                timestamp(222),
                BrokerCredentialSearchQuery::new(String::new()).expect("query"),
            )
            .expect_err("unauthorized metadata probe");
        assert!(matches!(
            error,
            BrokerRuntimeError::UseGrant(BrokerUseGrantError::AccessDenied)
        ));
        let rendered = error.to_string();
        assert_eq!(
            denial_text.get_or_insert_with(|| rendered.clone()),
            &rendered
        );
        for private_marker in [
            "Production API",
            "Unrelated account",
            "alice-private",
            "private.example",
            "private-tag",
        ] {
            assert!(!rendered.contains(private_marker));
        }
    }
    assert_eq!(
        runtime
            .device_state()
            .use_grants_for_consumer(consumer.consumer_id())
            .expect("search grant")
            .len(),
        1
    );
    runtime.shutdown().expect("shutdown");
}

#[test]
fn new_credential_matching_keeps_candidates_human_only_and_revalidates_selection() {
    let home = TestHome::new("credential-matching-runtime");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    let consumer = Consumer::new(
        [0x75; 32],
        "Matching integration Consumer".to_owned(),
        ObservedConsumerIdentity::default(),
        timestamp(110),
    )
    .expect("Consumer");
    state.insert_consumer(&consumer).expect("insert Consumer");
    drop(state);

    let vault = home.create_vault("Matching");
    let mut unlocked = VaultCore::new()
        .open_vault(OpenVaultRequest {
            path: vault.path.clone(),
        })
        .expect("open for fixture")
        .unlock(UnlockRequest {
            master_password: vault.password.clone(),
        })
        .expect("unlock for fixture");
    unlocked
        .create_item(VaultItemDraft {
            title: "GitHub production".to_owned(),
            content: VaultItemContent::Login(LoginItem {
                username: Some("private-account".to_owned()),
                password: Some(SecretBytes::new(b"selected-secret".to_vec())),
                urls: vec!["https://github.com/private".to_owned()],
                notes: None,
                totp_secret: Some(SecretBytes::new(b"JBSWY3DPEHPK3PXP".to_vec())),
            }),
            tags: vec!["release".to_owned(), "github".to_owned()],
            favorite: true,
        })
        .expect("matching credential");
    unlocked
        .create_item(VaultItemDraft {
            title: "Unrelated account".to_owned(),
            content: VaultItemContent::Login(LoginItem {
                username: Some("other-account".to_owned()),
                password: Some(SecretBytes::new(b"other-secret".to_vec())),
                urls: vec![],
                notes: None,
                totp_secret: None,
            }),
            tags: vec!["unrelated".to_owned()],
            favorite: false,
        })
        .expect("unrelated credential");
    drop(unlocked.lock());

    let mut runtime =
        BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store).expect("runtime");
    runtime
        .process()
        .vault_sessions()
        .open_vault(&vault.path)
        .expect("open vault");
    let vault_session_id = runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password.clone())
        .expect("unlock vault")
        .vault_session_id()
        .expect("session");

    runtime
        .set_machine_access_paused(true, timestamp(150))
        .expect("pause");
    assert!(matches!(
        runtime.admit_new_credential_request(
            BrokerNewCredentialRequest::new(
                consumer.consumer_id(),
                vault.vault_id,
                Capability::v1(CapabilityName::HttpRequest),
                "github release token".to_owned(),
            )
            .expect("request"),
        ),
        Err(BrokerRuntimeError::MachineAccess(
            BrokerMachineAccessError::Paused
        ))
    ));
    runtime
        .set_machine_access_paused(false, timestamp(160))
        .expect("resume");

    assert!(matches!(
        runtime.admit_new_credential_request(
            BrokerNewCredentialRequest::new(
                crate::ConsumerId::generate(),
                vault.vault_id,
                Capability::v1(CapabilityName::HttpRequest),
                "github".to_owned(),
            )
            .expect("unknown request"),
        ),
        Err(BrokerRuntimeError::CredentialMatching(
            BrokerCredentialMatchingError::ConsumerUnavailable
        ))
    ));

    let admitted = runtime
        .admit_new_credential_request(
            BrokerNewCredentialRequest::new(
                consumer.consumer_id(),
                vault.vault_id,
                Capability::v1(CapabilityName::HttpRequest),
                "private-account".to_owned(),
            )
            .expect("request"),
        )
        .expect("admit request");
    let admitted_debug = format!("{admitted:?}");
    assert!(!admitted_debug.contains("private-account"));
    assert!(!admitted_debug.contains("GitHub production"));
    assert!(admitted_debug.contains("<unavailable>"));

    runtime
        .set_machine_access_paused(true, timestamp(170))
        .expect("pause after admission");
    let review = runtime
        .review_new_credential_request(admitted, vault_session_id)
        .expect("human review");
    assert_eq!(review.description(), "private-account");
    assert_eq!(review.candidates().len(), 1);
    let candidate = &review.candidates()[0];
    assert_eq!(candidate.title(), "GitHub production");
    assert_eq!(candidate.secret_fields().len(), 1);
    assert_eq!(
        candidate.secret_fields()[0].kind(),
        SecretFieldKind::Password
    );
    let selection = BrokerCredentialCandidateSelection::new(
        candidate.credential_id(),
        candidate.secret_fields()[0].secret_field_id(),
    );

    let approved = runtime
        .approve_new_credential_selection(review, selection)
        .expect("human approval remains available");
    assert_eq!(approved.target().consumer_id(), consumer.consumer_id());
    assert_eq!(approved.target().field_scope().vault_id(), vault.vault_id);
    assert_eq!(
        approved.target().field_scope().credential_id(),
        selection.credential_id()
    );
    assert_eq!(
        approved.target().field_scope().secret_field_id(),
        selection.secret_field_id()
    );
    assert_eq!(approved.secret_kind(), SecretFieldKind::Password);
    assert_eq!(approved.metadata().title(), "GitHub production");
    assert_eq!(
        approved.metadata().authorized_field().secret_field_id(),
        selection.secret_field_id()
    );
    assert!(runtime
        .device_state()
        .access_rules_for_consumer(consumer.consumer_id())
        .expect("rules")
        .is_empty());
    assert!(runtime
        .device_state()
        .use_grants_for_consumer(consumer.consumer_id())
        .expect("grants")
        .is_empty());

    runtime
        .set_machine_access_paused(false, timestamp(180))
        .expect("resume for second request");
    let stale_admitted = runtime
        .admit_new_credential_request(
            BrokerNewCredentialRequest::new(
                consumer.consumer_id(),
                vault.vault_id,
                Capability::v1(CapabilityName::HttpRequest),
                "github".to_owned(),
            )
            .expect("stale request"),
        )
        .expect("admit stale request");
    let stale_review = runtime
        .review_new_credential_request(stale_admitted, vault_session_id)
        .expect("stale review");
    let stale_candidate = &stale_review.candidates()[0];
    let stale_selection = BrokerCredentialCandidateSelection::new(
        stale_candidate.credential_id(),
        stale_candidate.secret_fields()[0].secret_field_id(),
    );
    runtime
        .process()
        .vault_sessions()
        .lock_vault(vault.vault_id)
        .expect("lock vault");
    runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password)
        .expect("unlock fresh session");
    assert!(matches!(
        runtime.approve_new_credential_selection(stale_review, stale_selection),
        Err(BrokerRuntimeError::VaultSession(
            crate::BrokerVaultSessionError::VaultLocked
        ))
    ));

    runtime.shutdown().expect("shutdown");
}

#[test]
fn asynchronous_credential_approval_survives_only_with_safe_restart_context() {
    let home = TestHome::new("approval-runtime");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    let consumer = Consumer::new(
        [0x76; 32],
        "Approval integration Consumer".to_owned(),
        ObservedConsumerIdentity::default(),
        timestamp(110),
    )
    .expect("Consumer");
    state.insert_consumer(&consumer).expect("insert Consumer");
    drop(state);

    let vault = home.create_vault("Approval");
    let mut unlocked = VaultCore::new()
        .open_vault(OpenVaultRequest {
            path: vault.path.clone(),
        })
        .expect("open fixture")
        .unlock(UnlockRequest {
            master_password: vault.password.clone(),
        })
        .expect("unlock fixture");
    unlocked
        .create_item(VaultItemDraft {
            title: "GitHub releases".to_owned(),
            content: VaultItemContent::Login(LoginItem {
                username: Some("release-account".to_owned()),
                password: Some(SecretBytes::new(b"release-secret".to_vec())),
                urls: vec!["https://github.com/settings/tokens".to_owned()],
                notes: None,
                totp_secret: None,
            }),
            tags: vec!["release".to_owned()],
            favorite: true,
        })
        .expect("credential");
    drop(unlocked.lock());

    let runtime =
        BrokerRuntime::reopen_with_paths_at(home.paths.clone(), key_store.clone(), timestamp(120))
            .expect("runtime");
    assert_eq!(runtime.approval_restore_summary().expired(), 0);
    assert_eq!(
        runtime.approval_restore_summary().process_local_cancelled(),
        0
    );
    runtime
        .process()
        .vault_sessions()
        .open_vault(&vault.path)
        .expect("open vault");
    let vault_session_id = runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password.clone())
        .expect("unlock vault")
        .vault_session_id()
        .expect("session");

    let admitted = runtime
        .admit_new_credential_request(
            BrokerNewCredentialRequest::new(
                consumer.consumer_id(),
                vault.vault_id,
                Capability::v1(CapabilityName::HttpRequest),
                "release-account".to_owned(),
            )
            .expect("request"),
        )
        .expect("admit");
    let submission = runtime
        .submit_new_credential_approval(admitted, timestamp(130), timestamp(300))
        .expect("submit approval");
    let approval_id = submission.receipt().approval_request_id();
    let equivalent = runtime
        .admit_new_credential_request(
            BrokerNewCredentialRequest::new(
                consumer.consumer_id(),
                vault.vault_id,
                Capability::v1(CapabilityName::HttpRequest),
                "RELEASE-ACCOUNT".to_owned(),
            )
            .expect("equivalent request"),
        )
        .expect("admit equivalent");
    let coalesced = runtime
        .submit_new_credential_approval(equivalent, timestamp(131), timestamp(300))
        .expect("coalesce");
    assert!(coalesced.coalesced());
    assert_eq!(coalesced.receipt().approval_request_id(), approval_id);
    assert_eq!(
        runtime
            .poll_approval(consumer.consumer_id(), approval_id, timestamp(140))
            .expect("poll")
            .status(),
        ApprovalStatus::Pending
    );
    assert!(matches!(
        runtime.poll_approval(crate::ConsumerId::generate(), approval_id, timestamp(140)),
        Err(BrokerRuntimeError::Approval(
            BrokerApprovalError::ApprovalUnavailable
        ))
    ));

    let snapshots = runtime
        .pending_approvals_for_human(timestamp(140))
        .expect("human queue");
    assert_eq!(snapshots.len(), 1);
    assert_eq!(
        snapshots[0].credential_description(),
        Some("release-account")
    );
    runtime
        .set_machine_access_paused(true, timestamp(145))
        .expect("pause after admission");
    let review = runtime
        .review_pending_new_credential_approval(approval_id, vault_session_id, timestamp(150))
        .expect("review while paused");
    assert_eq!(review.candidates().len(), 1);
    let candidate = &review.candidates()[0];
    let selection = BrokerCredentialCandidateSelection::new(
        candidate.credential_id(),
        candidate.secret_fields()[0].secret_field_id(),
    );
    let approved = runtime
        .approve_new_credential_selection(review, selection)
        .expect("approve selection");
    assert_eq!(approved.target().consumer_id(), consumer.consumer_id());
    assert_eq!(
        runtime
            .resolve_approval(approval_id, BrokerApprovalDecision::Approve, timestamp(160))
            .expect("resolve approval")
            .status(),
        ApprovalStatus::Approved
    );
    assert!(runtime
        .device_state()
        .access_rules_for_consumer(consumer.consumer_id())
        .expect("rules")
        .is_empty());
    assert!(runtime
        .device_state()
        .use_grants_for_consumer(consumer.consumer_id())
        .expect("grants")
        .is_empty());

    let exact = runtime
        .submit_approval(
            ApprovalSubject::Access {
                target: approved.target(),
            },
            timestamp(170),
            timestamp(400),
        )
        .expect("exact approval");
    runtime
        .set_machine_access_paused(false, timestamp(171))
        .expect("resume");
    let pending_admitted = runtime
        .admit_new_credential_request(
            BrokerNewCredentialRequest::new(
                consumer.consumer_id(),
                vault.vault_id,
                Capability::v1(CapabilityName::HttpRequest),
                "GitHub releases".to_owned(),
            )
            .expect("pending request"),
        )
        .expect("admit pending request");
    let process_local = runtime
        .submit_new_credential_approval(pending_admitted, timestamp(172), timestamp(400))
        .expect("process-local approval");
    drop(runtime);

    let mut restarted =
        BrokerRuntime::reopen_with_paths_at(home.paths.clone(), key_store, timestamp(200))
            .expect("restart");
    assert_eq!(restarted.approval_restore_summary().expired(), 0);
    assert_eq!(
        restarted
            .approval_restore_summary()
            .process_local_cancelled(),
        1
    );
    assert_eq!(
        restarted
            .resume_approval(
                consumer.consumer_id(),
                exact.receipt().approval_request_id(),
                timestamp(201)
            )
            .expect("resume exact")
            .status(),
        ApprovalStatus::Pending
    );
    assert_eq!(
        restarted
            .resume_approval(
                consumer.consumer_id(),
                process_local.receipt().approval_request_id(),
                timestamp(201)
            )
            .expect("resume cancelled")
            .status(),
        ApprovalStatus::Cancelled
    );
    assert!(matches!(
        restarted.review_pending_new_credential_approval(
            process_local.receipt().approval_request_id(),
            VaultSessionId::generate(),
            timestamp(201)
        ),
        Err(BrokerRuntimeError::Approval(
            BrokerApprovalError::ContextUnavailable
        ))
    ));
    restarted.shutdown_at(timestamp(210)).expect("shutdown");
}

#[test]
fn runtime_revocation_scopes_preserve_human_session_and_pause_state() {
    let home = TestHome::new("revocation-runtime");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    let first = Consumer::new(
        [0x77; 32],
        "First revocation Consumer".to_owned(),
        ObservedConsumerIdentity::default(),
        timestamp(110),
    )
    .expect("first Consumer");
    let second = Consumer::new(
        [0x78; 32],
        "Second revocation Consumer".to_owned(),
        ObservedConsumerIdentity::default(),
        timestamp(111),
    )
    .expect("second Consumer");
    state.insert_consumer(&first).expect("insert first");
    state.insert_consumer(&second).expect("insert second");
    drop(state);

    let vault = home.create_vault("Revocation");
    let mut runtime =
        BrokerRuntime::reopen_with_paths_at(home.paths.clone(), key_store, timestamp(120))
            .expect("runtime");
    runtime
        .process()
        .vault_sessions()
        .open_vault(&vault.path)
        .expect("open vault");
    let vault_session_id = runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password)
        .expect("unlock")
        .vault_session_id()
        .expect("session");

    let first_removed_field = CredentialFieldScope::new(
        vault.vault_id,
        CredentialId::generate(),
        SecretFieldId::generate(),
    );
    let targets = [
        AuthorizationTarget::new(
            first.consumer_id(),
            first_removed_field,
            Capability::v1(CapabilityName::HttpRequest),
        ),
        AuthorizationTarget::new(
            first.consumer_id(),
            CredentialFieldScope::new(
                vault.vault_id,
                CredentialId::generate(),
                SecretFieldId::generate(),
            ),
            Capability::v1(CapabilityName::HttpRequest),
        ),
        AuthorizationTarget::new(
            second.consumer_id(),
            CredentialFieldScope::new(
                vault.vault_id,
                CredentialId::generate(),
                SecretFieldId::generate(),
            ),
            Capability::v1(CapabilityName::HttpRequest),
        ),
    ];
    let mut approval_ids = Vec::new();
    for (index, target) in targets.into_iter().enumerate() {
        let offset = i64::try_from(index).expect("offset");
        runtime
            .create_access_rule(
                BrokerAccessRuleApproval::after_user_approval(
                    target,
                    SecretFieldKind::ApiToken,
                    ConfirmationPolicy::AutomaticWhileUnlocked,
                    RuleLifetime::Persistent,
                    timestamp(200 + offset),
                )
                .expect("rule approval"),
            )
            .expect("rule");
        runtime
            .issue_automatic_rule_grant(
                target,
                SecretFieldKind::ApiToken,
                vault_session_id,
                timestamp(210 + offset),
                timestamp(800 + offset),
            )
            .expect("grant");
        approval_ids.push(
            runtime
                .submit_approval(
                    ApprovalSubject::Access { target },
                    timestamp(220 + offset),
                    timestamp(700 + offset),
                )
                .expect("approval")
                .receipt()
                .approval_request_id(),
        );
    }
    runtime
        .set_machine_access_paused(true, timestamp(230))
        .expect("pause");

    let field_summary = runtime
        .revoke_consumer_field_access(first.consumer_id(), first_removed_field)
        .expect("field revocation");
    assert_eq!(field_summary.kind(), BrokerRevocationKind::ConsumerField);
    assert_eq!(field_summary.access_rules_removed(), 1);
    assert_eq!(field_summary.use_grants_removed(), 1);
    assert_eq!(field_summary.approvals_removed(), 1);
    assert_eq!(
        runtime
            .device_state()
            .access_rules_for_consumer(first.consumer_id())
            .expect("first rules")
            .len(),
        1
    );
    assert_eq!(
        runtime
            .device_state()
            .access_rules_for_consumer(second.consumer_id())
            .expect("second rules")
            .len(),
        1
    );

    let consumer_summary = runtime
        .revoke_consumer_access(first.consumer_id())
        .expect("Consumer revocation");
    assert_eq!(consumer_summary.kind(), BrokerRevocationKind::Consumer);
    assert_eq!(consumer_summary.consumers_removed(), 1);
    assert_eq!(consumer_summary.access_rules_removed(), 1);
    assert_eq!(consumer_summary.use_grants_removed(), 1);
    assert_eq!(consumer_summary.approvals_removed(), 1);
    assert!(runtime
        .device_state()
        .consumer(first.consumer_id())
        .expect("first Consumer")
        .is_none());
    assert!(runtime
        .device_state()
        .consumer(second.consumer_id())
        .expect("second Consumer")
        .is_some());

    let pairing_key = SigningKey::from_bytes(&[0x79; 32]);
    runtime
        .begin_pairing(
            ConsumerPairingProposal::new(
                pairing_key.verifying_key().to_bytes(),
                [0x7a; 32],
                crate::BrokerProtocolVersion::current(),
            )
            .expect("pairing proposal"),
            ObservedConsumerIdentity::default(),
        )
        .expect("pending pairing");
    assert_eq!(runtime.pending_pairings().expect("pairings").len(), 1);

    let global_summary = runtime
        .revoke_all_apps_and_tools_access()
        .expect("global revocation");
    assert_eq!(global_summary.kind(), BrokerRevocationKind::Global);
    assert_eq!(global_summary.consumers_removed(), 1);
    assert_eq!(global_summary.access_rules_removed(), 1);
    assert_eq!(global_summary.use_grants_removed(), 1);
    assert_eq!(global_summary.approvals_removed(), 1);
    assert_eq!(global_summary.pending_pairings_cancelled(), 1);
    assert!(runtime
        .device_state()
        .consumers()
        .expect("Consumers")
        .is_empty());
    assert!(runtime.pending_pairings().expect("pairings").is_empty());
    assert!(runtime.machine_access().is_paused().expect("pause"));
    assert_eq!(
        runtime
            .process()
            .vault_sessions()
            .snapshot(vault.vault_id)
            .expect("session")
            .vault_session_id(),
        Some(vault_session_id)
    );
    assert!(matches!(
        runtime.poll_approval(second.consumer_id(), approval_ids[2], timestamp(240)),
        Err(BrokerRuntimeError::Approval(
            BrokerApprovalError::ApprovalUnavailable
        ))
    ));
    assert!(!runtime
        .revoke_all_apps_and_tools_access()
        .expect("repeat global revocation")
        .changed());
    runtime.shutdown_at(timestamp(250)).expect("shutdown");
}

#[test]
fn immutable_consumer_identity_blocks_presentation_spoofing() {
    let home = TestHome::new("authorization-spoofing");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    let shared_identity = ObservedConsumerIdentity::new(
        Some("shared-adapter".to_owned()),
        Some("app.keptnear.shared".to_owned()),
        None,
        Some([0x80; 32]),
    )
    .expect("shared identity");
    let owner = Consumer::new(
        [0x81; 32],
        "Shared presentation".to_owned(),
        shared_identity.clone(),
        timestamp(110),
    )
    .expect("owner");
    let imitator = Consumer::new(
        [0x82; 32],
        "Shared presentation".to_owned(),
        shared_identity,
        timestamp(111),
    )
    .expect("imitator");
    state.insert_consumer(&owner).expect("insert owner");
    state.insert_consumer(&imitator).expect("insert imitator");
    drop(state);

    let vault = home.create_vault("Spoofing");
    let mut runtime =
        BrokerRuntime::reopen_with_paths_at(home.paths.clone(), key_store, timestamp(120))
            .expect("runtime");
    runtime
        .process()
        .vault_sessions()
        .open_vault(&vault.path)
        .expect("open vault");
    let vault_session_id = runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password)
        .expect("unlock")
        .vault_session_id()
        .expect("session");
    let field_scope = CredentialFieldScope::new(
        vault.vault_id,
        CredentialId::generate(),
        SecretFieldId::generate(),
    );
    let owner_target = AuthorizationTarget::new(
        owner.consumer_id(),
        field_scope,
        Capability::v1(CapabilityName::HttpRequest),
    );
    runtime
        .create_access_rule(
            BrokerAccessRuleApproval::after_user_approval(
                owner_target,
                SecretFieldKind::ApiToken,
                ConfirmationPolicy::AutomaticWhileUnlocked,
                RuleLifetime::Persistent,
                timestamp(130),
            )
            .expect("rule approval"),
        )
        .expect("owner rule");
    let grant = runtime
        .issue_allow_once_grant(
            BrokerAllowOnceApproval::after_user_approval(
                owner_target,
                SecretFieldKind::ApiToken,
                vault_session_id,
                timestamp(140),
                timestamp(300),
            )
            .expect("Allow Once"),
        )
        .expect("owner grant");
    let approval_id = runtime
        .submit_approval(
            ApprovalSubject::Access {
                target: owner_target,
            },
            timestamp(141),
            timestamp(300),
        )
        .expect("owner approval")
        .receipt()
        .approval_request_id();
    let imitator_target = AuthorizationTarget::new(
        imitator.consumer_id(),
        field_scope,
        Capability::v1(CapabilityName::HttpRequest),
    );

    assert_eq!(
        runtime
            .evaluate_access_rule(imitator_target, SecretFieldKind::ApiToken, timestamp(150),)
            .expect("imitator rule evaluation"),
        BrokerAccessRuleEvaluation::NoMatchingRule
    );
    let grant_error = runtime
        .authorize_use_grant(
            grant.grant().use_grant_id(),
            imitator_target,
            SecretFieldKind::ApiToken,
            vault_session_id,
            timestamp(151),
        )
        .expect_err("imitator cannot use owner grant");
    assert!(matches!(
        grant_error,
        BrokerRuntimeError::UseGrant(BrokerUseGrantError::AccessDenied)
    ));
    assert!(matches!(
        runtime.poll_approval(imitator.consumer_id(), approval_id, timestamp(152)),
        Err(BrokerRuntimeError::Approval(
            BrokerApprovalError::ApprovalUnavailable
        ))
    ));
    assert_eq!(
        runtime
            .device_state()
            .use_grants_for_consumer(owner.consumer_id())
            .expect("owner grant retained")
            .len(),
        1
    );
    assert!(runtime
        .authorize_use_grant(
            grant.grant().use_grant_id(),
            owner_target,
            SecretFieldKind::ApiToken,
            vault_session_id,
            timestamp(153),
        )
        .expect("owner use")
        .consumed());
    let rendered = grant_error.to_string();
    assert!(!rendered.contains("Shared presentation"));
    assert!(!rendered.contains("shared-adapter"));
    runtime.shutdown_at(timestamp(160)).expect("shutdown");
}

#[test]
fn pairing_proof_and_one_operation_grant_replays_do_not_restore_access() {
    let home = TestHome::new("authorization-replay");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    drop(state);
    let mut runtime =
        BrokerRuntime::reopen_with_paths_at(home.paths.clone(), key_store, timestamp(120))
            .expect("runtime");
    let signing_key = SigningKey::from_bytes(&[0x83; 32]);
    let challenge = runtime
        .begin_pairing(
            ConsumerPairingProposal::new(
                signing_key.verifying_key().to_bytes(),
                [0x84; 32],
                BrokerProtocolVersion::current(),
            )
            .expect("pairing proposal"),
            ObservedConsumerIdentity::default(),
        )
        .expect("pairing challenge");
    let proof_challenge = runtime
        .approve_pairing(
            challenge.pairing_request_id(),
            BrokerPairingUserApproval::after_user_approval(
                "Replay test Consumer".to_owned(),
                timestamp(130),
            ),
        )
        .expect("pairing approval");
    let proof = signing_key.sign(proof_challenge.transcript()).to_bytes();
    let completion = runtime
        .complete_pairing(challenge.pairing_request_id(), proof)
        .expect("pairing completion");
    assert!(matches!(
        runtime.complete_pairing(challenge.pairing_request_id(), proof),
        Err(BrokerRuntimeError::Pairing(
            BrokerPairingError::RequestUnavailable
        ))
    ));

    let vault = home.create_vault("Replay");
    runtime
        .process()
        .vault_sessions()
        .open_vault(&vault.path)
        .expect("open vault");
    let vault_session_id = runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password)
        .expect("unlock")
        .vault_session_id()
        .expect("session");
    let target = AuthorizationTarget::new(
        completion.consumer_id(),
        CredentialFieldScope::new(
            vault.vault_id,
            CredentialId::generate(),
            SecretFieldId::generate(),
        ),
        Capability::v1(CapabilityName::ProcessRun),
    );
    let grant = runtime
        .issue_allow_once_grant(
            BrokerAllowOnceApproval::after_user_approval(
                target,
                SecretFieldKind::GenericSecret,
                vault_session_id,
                timestamp(140),
                timestamp(300),
            )
            .expect("Allow Once"),
        )
        .expect("one-operation grant");
    let grant_id = grant.grant().use_grant_id();
    assert!(runtime
        .authorize_use_grant(
            grant_id,
            target,
            SecretFieldKind::GenericSecret,
            vault_session_id,
            timestamp(150),
        )
        .expect("first use")
        .consumed());
    assert!(matches!(
        runtime.authorize_use_grant(
            grant_id,
            target,
            SecretFieldKind::GenericSecret,
            vault_session_id,
            timestamp(151),
        ),
        Err(BrokerRuntimeError::UseGrant(
            BrokerUseGrantError::AccessDenied
        ))
    ));
    assert!(runtime
        .device_state()
        .access_rules_for_consumer(completion.consumer_id())
        .expect("rules")
        .is_empty());
    assert!(runtime
        .device_state()
        .use_grants_for_consumer(completion.consumer_id())
        .expect("grants")
        .is_empty());
    runtime.shutdown_at(timestamp(160)).expect("shutdown");
}

#[test]
fn stale_grant_cannot_cross_unlock_session_or_process_identity() {
    let home = TestHome::new("authorization-stale-grant");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    let consumer = Consumer::new(
        [0x85; 32],
        "Stale grant Consumer".to_owned(),
        ObservedConsumerIdentity::default(),
        timestamp(110),
    )
    .expect("Consumer");
    state.insert_consumer(&consumer).expect("insert Consumer");
    drop(state);

    let vault = home.create_vault("StaleGrant");
    let runtime =
        BrokerRuntime::reopen_with_paths_at(home.paths.clone(), key_store.clone(), timestamp(120))
            .expect("runtime");
    runtime
        .process()
        .vault_sessions()
        .open_vault(&vault.path)
        .expect("open vault");
    let first_session = runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password.clone())
        .expect("first unlock")
        .vault_session_id()
        .expect("first session");
    let target = AuthorizationTarget::new(
        consumer.consumer_id(),
        CredentialFieldScope::new(
            vault.vault_id,
            CredentialId::generate(),
            SecretFieldId::generate(),
        ),
        Capability::v1(CapabilityName::ProcessRun),
    );
    runtime
        .create_access_rule(
            BrokerAccessRuleApproval::after_user_approval(
                target,
                SecretFieldKind::PrivateKey,
                ConfirmationPolicy::AutomaticWhileUnlocked,
                RuleLifetime::Persistent,
                timestamp(130),
            )
            .expect("rule approval"),
        )
        .expect("rule");
    let stale_grant = runtime
        .issue_automatic_rule_grant(
            target,
            SecretFieldKind::PrivateKey,
            first_session,
            timestamp(140),
            timestamp(500),
        )
        .expect("first-session grant");
    let stale_grant_id = stale_grant.grant().use_grant_id();

    runtime
        .process()
        .vault_sessions()
        .lock_vault(vault.vault_id)
        .expect("lock")
        .expect("lock event");
    let second_session = runtime
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password.clone())
        .expect("second unlock")
        .vault_session_id()
        .expect("second session");
    assert_ne!(first_session, second_session);
    assert!(matches!(
        runtime.authorize_use_grant(
            stale_grant_id,
            target,
            SecretFieldKind::PrivateKey,
            first_session,
            timestamp(150),
        ),
        Err(BrokerRuntimeError::UseGrant(
            BrokerUseGrantError::GrantExpired
        ))
    ));
    assert!(matches!(
        runtime.authorize_use_grant(
            stale_grant_id,
            target,
            SecretFieldKind::PrivateKey,
            second_session,
            timestamp(151),
        ),
        Err(BrokerRuntimeError::UseGrant(
            BrokerUseGrantError::AccessDenied
        ))
    ));
    assert_eq!(
        runtime
            .device_state()
            .use_grants_for_consumer(consumer.consumer_id())
            .expect("pending stale grant")
            .len(),
        1
    );
    drop(runtime);

    let mut restarted =
        BrokerRuntime::reopen_with_paths_at(home.paths.clone(), key_store, timestamp(200))
            .expect("restart");
    assert_eq!(restarted.stale_use_grants_removed(), 1);
    assert!(restarted
        .device_state()
        .use_grants_for_consumer(consumer.consumer_id())
        .expect("stale grants removed")
        .is_empty());
    assert_eq!(
        restarted
            .device_state()
            .access_rules_for_consumer(consumer.consumer_id())
            .expect("persistent rule")
            .len(),
        1
    );
    restarted
        .process()
        .vault_sessions()
        .open_vault(&vault.path)
        .expect("reopen vault");
    let restarted_session = restarted
        .process()
        .vault_sessions()
        .unlock_with_master_password(vault.vault_id, vault.password)
        .expect("unlock after restart")
        .vault_session_id()
        .expect("restart session");
    let replacement = restarted
        .issue_automatic_rule_grant(
            target,
            SecretFieldKind::PrivateKey,
            restarted_session,
            timestamp(210),
            timestamp(500),
        )
        .expect("replacement grant");
    assert_ne!(replacement.grant().use_grant_id(), stale_grant_id);
    assert!(restarted
        .authorize_use_grant(
            replacement.grant().use_grant_id(),
            target,
            SecretFieldKind::PrivateKey,
            restarted_session,
            timestamp(220),
        )
        .is_ok());
    restarted.shutdown_at(timestamp(230)).expect("shutdown");
}

#[test]
fn ciphertext_corruption_blocks_runtime_without_replacing_state_or_key() {
    let home = TestHome::new("corrupt");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    drop(state);
    let key_before = key_store.bytes().expect("device key");
    let database_before = fs::read(home.database_path()).expect("database before tamper");
    let tampered_byte = database_before
        .get(100)
        .copied()
        .expect("database contains authenticated page bytes")
        ^ 0xff;
    let mut database = OpenOptions::new()
        .read(true)
        .write(true)
        .open(home.database_path())
        .expect("open database");
    database.seek(SeekFrom::Start(100)).expect("seek");
    database.write_all(&[tampered_byte]).expect("tamper");
    database.sync_all().expect("sync tamper");
    drop(database);
    let tampered = fs::read(home.database_path()).expect("tampered database");

    let error = BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store.clone())
        .expect_err("corrupt state must block startup");

    assert!(matches!(
        error,
        BrokerRuntimeError::LocalData(BrokerLocalDataError::DeviceState(
            DeviceStateError::AuthenticationFailed
        ))
    ));
    assert_eq!(fs::read(home.database_path()).expect("database"), tampered);
    assert_eq!(key_store.bytes().expect("unchanged key"), key_before);
    assert_path_free(&error, &home.path);
}

#[test]
fn owner_only_socket_routes_a_bounded_authenticated_human_control_client() {
    let home = TestHome::new_short("hc");
    let key_store = MemoryKeyStore::default();
    let mut runtime = BrokerRuntime::open_or_initialize_with_paths_at(
        home.paths.clone(),
        key_store,
        timestamp(100),
    )
    .expect("runtime");
    let dispatcher = HumanControlDispatcher::new(
        runtime.process().broker_instance_id(),
        MemoryControllerKeyStore::seeded(0x61),
    );
    let signing_key =
        ControllerSigningKey::from_stored_bytes(vec![0x61; 32]).expect("controller key");
    let listener = UnixBrokerListener::bind(&home.paths).expect("listener");
    let metadata = fs::symlink_metadata(listener.socket_path()).expect("socket metadata");
    assert_eq!(metadata.mode() & 0o777, 0o600);
    let zero_timeout = match UnixBrokerConnection::connect_with_timeout(&home.paths, Duration::ZERO)
    {
        Ok(_) => panic!("zero timeout must fail"),
        Err(error) => error,
    };
    assert_eq!(
        zero_timeout,
        UnixBrokerTransportError::Io {
            entry: UnixBrokerTransportEntry::Socket,
            operation: UnixBrokerTransportOperation::Connect,
            kind: std::io::ErrorKind::TimedOut,
        }
    );

    let paths = home.paths.clone();
    let client = thread::spawn(move || {
        let mut connection =
            UnixBrokerConnection::connect_with_timeout(&paths, Duration::from_secs(2))
                .expect("bounded connect");
        connection
            .set_operation_timeout(Some(Duration::from_secs(2)))
            .expect("operation timeout");
        let HumanControlClientResponse::Success(hello) =
            exchange_human_control(&mut connection, &human_control_hello())
        else {
            panic!("hello success");
        };
        assert!(hello.has_complete_operation_catalog());

        let challenge_request =
            HumanControlRequest::ControllerChallenge(ControllerChallengeRequest::new(
                signing_key.controller_id(),
                ControllerNonce::from_bytes([0x62; 32]),
            ));
        let HumanControlClientResponse::Success(challenge) =
            exchange_human_control(&mut connection, &challenge_request)
        else {
            panic!("challenge success");
        };
        let challenge = challenge
            .controller_challenge()
            .expect("controller challenge");
        let HumanControlClientResponse::Success(authenticated) = exchange_human_control(
            &mut connection,
            &HumanControlRequest::ControllerAuthenticate(challenge.prove(&signing_key)),
        ) else {
            panic!("authentication success");
        };
        assert_eq!(
            authenticated.authenticated_session().expect("session").0,
            signing_key.controller_id()
        );
        let HumanControlClientResponse::Success(readiness) =
            exchange_human_control(&mut connection, &HumanControlRequest::ReadinessGet)
        else {
            panic!("readiness success");
        };
        assert_eq!(
            readiness
                .result()
                .get("humanControlSchema")
                .and_then(serde_json::Value::as_str),
            Some(HUMAN_CONTROL_SCHEMA_ID)
        );
        connection.shutdown().expect("client shutdown");
    });

    assert_eq!(
        listener
            .serve_one_routed(&mut runtime, &dispatcher)
            .expect("routed serve"),
        (
            BrokerConnectionClass::HumanControl,
            BrokerConnectionExit::PeerClosed
        )
    );
    client.join().expect("client");
    runtime
        .shutdown_at(timestamp(200))
        .expect("runtime shutdown");
    listener.shutdown().expect("listener shutdown");
}

#[test]
fn missing_device_key_blocks_runtime_without_generating_replacement() {
    let home = TestHome::new("missing-key");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    drop(state);
    let database_before = fs::read(home.database_path()).expect("database before");
    key_store.forget();

    let error = BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store.clone())
        .expect_err("missing key must block startup");

    assert!(matches!(
        error,
        BrokerRuntimeError::LocalData(BrokerLocalDataError::DeviceKey(DeviceKeyError::Missing))
    ));
    assert!(key_store.bytes().is_none());
    assert_eq!(
        fs::read(home.database_path()).expect("database after"),
        database_before
    );
    assert_path_free(&error, &home.path);
}

#[test]
fn wrong_device_key_blocks_runtime_without_overwriting_either_side() {
    let home = TestHome::new("wrong-key");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    drop(state);
    let database_before = fs::read(home.database_path()).expect("database before");
    let wrong_key = vec![0x9a; crate::DEVICE_ROOT_KEY_LENGTH];
    key_store.replace(wrong_key.clone());

    let error = BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store.clone())
        .expect_err("wrong key must block startup");

    assert!(matches!(
        error,
        BrokerRuntimeError::LocalData(BrokerLocalDataError::DeviceState(
            DeviceStateError::AuthenticationFailed
        ))
    ));
    assert_eq!(key_store.bytes().expect("wrong key retained"), wrong_key);
    assert_eq!(
        fs::read(home.database_path()).expect("database after"),
        database_before
    );
    assert_path_free(&error, &home.path);
}

#[test]
fn insecure_database_permissions_block_runtime_and_retain_authority() {
    let home = TestHome::new("permissions");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    drop(state);
    let key_before = key_store.bytes().expect("device key");
    fs::set_permissions(home.database_path(), fs::Permissions::from_mode(0o644))
        .expect("broaden database");

    let error = BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store.clone())
        .expect_err("unsafe permissions must block startup");

    assert!(matches!(
        error,
        BrokerRuntimeError::LocalData(BrokerLocalDataError::DeviceState(
            DeviceStateError::InsecurePermissions {
                entry: DeviceStateFileEntry::Database,
                mode: 0o644
            }
        ))
    ));
    assert_eq!(key_store.bytes().expect("unchanged key"), key_before);
    assert!(home.database_path().exists());
    assert_path_free(&error, &home.path);
}

#[test]
fn missing_database_blocks_runtime_without_silent_reinitialization() {
    let home = TestHome::new("missing-database");
    let key_store = MemoryKeyStore::default();
    let state = initialize_state(&home, &key_store);
    drop(state);
    let key_before = key_store.bytes().expect("device key");
    fs::remove_file(home.database_path()).expect("remove database");

    let error = BrokerRuntime::reopen_with_paths(home.paths.clone(), key_store.clone())
        .expect_err("missing database must block startup");

    assert!(matches!(
        error,
        BrokerRuntimeError::LocalData(BrokerLocalDataError::DeviceState(DeviceStateError::Missing))
    ));
    assert!(!home.database_path().exists());
    assert_eq!(key_store.bytes().expect("unchanged key"), key_before);
    assert_path_free(&error, &home.path);
}
