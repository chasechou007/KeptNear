#![deny(unsafe_code)]
#![deny(missing_docs)]

//! Local credential Broker foundations.
//!
//! This crate owns device-local paths, state, IPC, and authorization
//! infrastructure. It does not parse portable vault records.

mod access_rule;
mod approval;
mod audit;
mod authentication;
mod capability_protocol;
mod component_metadata;
mod controller_authentication;
mod controller_authority_contract;
mod controller_key;
mod credential_matching;
mod credential_search;
mod device_key;
mod dispatcher;
mod grant_invalidation;
mod http_request;
mod human_control;
mod human_control_dispatcher;
mod human_control_protocol;
mod human_control_types;
mod human_control_wire;
#[cfg(all(test, unix))]
mod integration_tests;
mod local_data;
mod machine_access;
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos_keychain;
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos_peer_evidence;
mod outbound_operation;
mod pairing;
mod paths;
mod process;
mod process_lock;
#[allow(unsafe_code)]
mod process_run;
mod protocol;
mod readiness;
mod revocation;
mod runtime;
#[allow(unsafe_code)]
mod sqlcipher_ffi;
mod state_model;
mod state_schema;
mod state_store;
#[cfg(target_os = "macos")]
mod unix_transport;
mod usage_profile;
mod usage_profile_template;
mod use_grant;
mod vault_session;

pub use access_rule::{
    BrokerAccessRuleApproval, BrokerAccessRuleCreation, BrokerAccessRuleError,
    BrokerAccessRuleEvaluation,
};
pub use approval::{
    BrokerApprovalDecision, BrokerApprovalError, BrokerApprovalReceipt,
    BrokerApprovalRestoreSummary, BrokerApprovalSubmission, BrokerApprovalWaitOutcome,
    BrokerHumanApprovalSnapshot, MAX_APPROVAL_LIFETIME, MAX_APPROVAL_WAIT, MAX_PENDING_APPROVALS,
};
pub use audit::{
    BrokerAuditClearConfirmation, BrokerAuditClearSummary, BrokerAuditCursor, BrokerAuditError,
    BrokerAuditExport, BrokerAuditFilter, BrokerAuditPage, MAX_AUDIT_VIEW_EVENTS,
};
pub use authentication::{
    broker_authentication_transcript, BrokerAuthenticationChallenge,
    BrokerAuthenticationCompletion, BrokerAuthenticationError, AUTHENTICATION_CHALLENGE_TTL,
    AUTHENTICATION_NONCE_LENGTH, AUTHENTICATION_PROOF_LENGTH,
};
pub use capability_protocol::{
    BrokerAccessReceiptResponse, BrokerAccessRequest, BrokerAccessResponse,
    BrokerAccessSubmissionResponse, BrokerAccessWaitResponse, BrokerActiveGrantMetadata,
    BrokerCredentialMetadataResponse, BrokerCredentialOperationTarget,
    BrokerCredentialSearchRequest, BrokerCredentialSearchResponse, BrokerGrantRevokeRequest,
    BrokerGrantRevokeResponse, BrokerGrantStatus, BrokerGrantStatusRequest,
    BrokerGrantStatusResponse, BrokerHttpCapabilityHeader, BrokerHttpCapabilityRequest,
    BrokerHttpCapabilityResponse, BrokerProcessCapabilityEnvironment,
    BrokerProcessCapabilityRequest, BrokerProcessCapabilityResponse,
};
pub use component_metadata::{
    ComponentBrokerProtocol, ComponentMetadata, ComponentMetadataError, PackagedComponent,
    COMPONENT_METADATA_SCHEMA,
};
pub use controller_authentication::{
    ControllerAuthenticationChallenge, ControllerAuthenticationCompletion,
    ControllerAuthenticationConnection, ControllerAuthenticationError,
    ControllerAuthenticationMode, ControllerAuthenticationProof, ControllerAuthenticationService,
    ControllerChallengeRequest,
};
pub use controller_authority_contract::{
    controller_authentication_transcript, controller_bootstrap_transcript,
    controller_enable_disposition, derive_controller_id, ControllerAuthorityContractError,
    ControllerAuthorityPresence, ControllerEnableDisposition, ControllerKeychainAccessGroup,
    ControllerKeychainContract, ControllerKeychainPrincipal, ControllerRemovalOrder,
    ControllerRotationPolicy, ControllerTranscriptFields, CONTROLLER_AUTHENTICATION_DOMAIN,
    CONTROLLER_AUTHORITY_CONTRACT_ID, CONTROLLER_BOOTSTRAP_DOMAIN, CONTROLLER_CHALLENGE_TTL,
    CONTROLLER_FAILURE_WINDOW, CONTROLLER_ID_LENGTH, CONTROLLER_KEYCHAIN_ACCESS_GROUP_SUFFIX,
    CONTROLLER_KEYCHAIN_ACCOUNT, CONTROLLER_KEYCHAIN_CONTRACT, CONTROLLER_KEYCHAIN_LABEL,
    CONTROLLER_KEYCHAIN_PRINCIPALS, CONTROLLER_KEYCHAIN_REMOVAL_MARKER_ACCOUNT,
    CONTROLLER_KEYCHAIN_REMOVAL_MARKER_VALUE, CONTROLLER_KEYCHAIN_SERVICE, CONTROLLER_NONCE_LENGTH,
    CONTROLLER_PROTOCOL_ID_LENGTH, CONTROLLER_PUBLIC_KEY_LENGTH, CONTROLLER_REMOVAL_ORDER,
    CONTROLLER_ROLE, CONTROLLER_ROTATION_POLICY, CONTROLLER_SIGNATURE_LENGTH,
    CONTROLLER_SIGNING_ALGORITHM, CONTROLLER_SIGNING_PREFIX_LENGTH, CONTROLLER_SIGNING_SEED_LENGTH,
    MAX_CONTROLLER_FAILURES_GLOBALLY, MAX_CONTROLLER_FAILURES_PER_IDENTITY,
    MAX_OUTSTANDING_CONTROLLER_CHALLENGES_PER_CONNECTION,
};
pub use controller_key::{
    is_controller_removal_marker, ControllerAuthorityError, ControllerAuthorityManager,
    ControllerAuthorityRecord, ControllerBootstrapMode, ControllerKeyStore,
    ControllerKeyStoreError, ControllerKeyStoreOperation, ControllerSignature,
    ControllerSigningKey, PreparedControllerAuthority,
};
pub use credential_matching::{
    BrokerAdmittedCredentialRequest, BrokerApprovedCredentialSelection,
    BrokerCredentialCandidateSelection, BrokerCredentialMatchingError,
    BrokerHumanCredentialCandidate, BrokerHumanCredentialReview, BrokerHumanSecretFieldCandidate,
    BrokerNewCredentialRequest, MAX_CREDENTIAL_REQUEST_DESCRIPTION_BYTES,
    MAX_HUMAN_CREDENTIAL_CANDIDATES,
};
pub use credential_search::{
    BrokerAuthorizedFieldMetadata, BrokerCredentialMetadata, BrokerCredentialSearchError,
    BrokerCredentialSearchQuery, BrokerCredentialSearchResult, MAX_CREDENTIAL_SEARCH_QUERY_BYTES,
};
pub use device_key::{
    DeviceKeyError, DeviceKeyManager, DeviceKeyStore, DeviceKeyStoreError, DeviceKeyStoreOperation,
    DeviceRootKey, DEVICE_ROOT_KEY_LENGTH,
};
pub use dispatcher::{
    BrokerConnectionState, BrokerDispatchError, BrokerDispatchOutcome, BrokerDispatcher,
};
pub use grant_invalidation::{
    BrokerGrantInvalidationError, BrokerGrantInvalidationSummary, BrokerGrantInvalidator,
};
pub use http_request::{
    BrokerHttpHeader, BrokerHttpMethod, BrokerHttpRequest, BrokerHttpRequestError,
    BrokerHttpResponse, HTTP_REQUEST_TIMEOUT, MAX_HTTP_HEADER_NAME_BYTES,
    MAX_HTTP_HEADER_VALUE_BYTES, MAX_HTTP_REQUEST_BODY_BYTES, MAX_HTTP_REQUEST_HEADERS,
    MAX_HTTP_REQUEST_HEADER_BYTES, MAX_HTTP_RESPONSE_BODY_BYTES, MAX_HTTP_URL_BYTES,
};
pub use human_control::{
    BrokerAppsToolsSnapshot, BrokerConsumerAuditSummary, BrokerConsumerDetail,
    BrokerConsumerIdentityEvidence, BrokerConsumerSummary, BrokerFieldGrantSummary,
    BrokerHumanControlError, BrokerPendingRequest, BrokerPendingRequestId,
    BrokerPendingRequestKind, BrokerPendingRequestQueue, BrokerUsageProfileSummary,
    MAX_CONSUMER_DETAIL_AUDIT_EVENTS,
};
pub use human_control_dispatcher::{
    HumanControlAuditPage, HumanControlConnectionPhase, HumanControlConnectionState,
    HumanControlCredentialCandidate, HumanControlCredentialReview, HumanControlDispatchError,
    HumanControlDispatcher, HumanControlPendingRequest, HumanControlRequest, HumanControlResponse,
    HumanControlSecretFieldCandidate, HumanControlUsageProfileCatalog,
    HumanControlVaultUnlockCredential,
};
pub use human_control_protocol::{
    HumanControlAuthenticationRequirement, HumanControlFailureCode, HumanControlLimits,
    HumanControlOperation, HumanControlOperationContract, HumanControlProtocolFailure,
    HumanControlProtocolValidationError, HumanControlProtocolVersion,
    HumanControlProtocolVersionRange, HumanControlRequestSchema, HumanControlRequestSecretClass,
    HumanControlRequiredAction, HumanControlResponseSchema, HumanControlResultSecrecy,
    HumanControlVersionOffer, HUMAN_CONTROL_CONSUMER_REVOKE_SCOPE,
    HUMAN_CONTROL_CONTROLLER_LEASE_TTL, HUMAN_CONTROL_DENY_DECISION, HUMAN_CONTROL_FAILURE_CODES,
    HUMAN_CONTROL_OPERATION_CONTRACTS, HUMAN_CONTROL_PROTOCOL_MAJOR, HUMAN_CONTROL_PROTOCOL_MINOR,
    HUMAN_CONTROL_PROTOCOL_NAME, HUMAN_CONTROL_REQUIRED_ACTIONS, HUMAN_CONTROL_SCHEMA_ID,
    HUMAN_CONTROL_SHUTDOWN_REASON, MAX_HUMAN_CONTROL_AUDIT_CLEAR_CONFIRMATIONS,
    MAX_HUMAN_CONTROL_AUDIT_EVENTS, MAX_HUMAN_CONTROL_AUTH_LENGTH,
    MAX_HUMAN_CONTROL_COLLECTION_ITEMS, MAX_HUMAN_CONTROL_FRAME_LENGTH,
    MAX_HUMAN_CONTROL_HELLO_LENGTH, MAX_HUMAN_CONTROL_INPUT_TEXT_BYTES,
    MAX_HUMAN_CONTROL_NEGOTIATION_ID_BYTES, MAX_HUMAN_CONTROL_REQUEST_LENGTH,
    MAX_HUMAN_CONTROL_RESPONSE_LENGTH, MAX_HUMAN_CONTROL_SCHEMA_IDS,
    MAX_HUMAN_CONTROL_UNLOCK_CREDENTIAL_BYTES, MAX_HUMAN_CONTROL_UNLOCK_LENGTH,
    MAX_HUMAN_CONTROL_VERSION_RANGES,
};
pub use human_control_types::{
    ControllerDeadline, ControllerId, ControllerNonce, ControllerSessionId,
    HumanControlAuditConfirmationId, HumanControlRequestId, HumanControlTypeParseError,
};
pub use human_control_wire::{
    decode_human_control_wire_envelope, read_human_control_frame, write_human_control_frame,
    HumanControlFrame, HumanControlWireEnvelope, HumanControlWireError,
};
pub use local_data::{
    BrokerLocalDataClearConfirmation, BrokerLocalDataClearSummary, BrokerLocalDataError,
    BrokerLocalDataManager,
};
pub use machine_access::{
    BrokerMachineAccessError, BrokerMachineAccessGate, BrokerMachineAccessTransition,
};
#[cfg(target_os = "macos")]
pub use macos_keychain::{MacOsControllerKeyStore, MacOsDeviceKeyStore};
pub use outbound_operation::{
    BrokerOutboundOperationAuthorization, BrokerOutboundOperationError,
    BrokerOutboundOperationOutcome,
};
pub use pairing::{
    consumer_pairing_transcript, BrokerConsumerPairingProgress, BrokerConsumerPairingSnapshot,
    BrokerPairingAuthorizationEffect, BrokerPairingChallenge, BrokerPairingCompletion,
    BrokerPairingError, BrokerPairingIdentityEvidence, BrokerPairingProofChallenge,
    BrokerPairingRequestSnapshot, BrokerPairingRequestStatus, BrokerPairingUserApproval,
    ConsumerPairingProposal, PairingComparisonCode, MAX_PENDING_PAIRING_REQUESTS,
    PAIRING_NONCE_LENGTH, PAIRING_PROOF_LENGTH, PAIRING_PUBLIC_KEY_LENGTH, PAIRING_REQUEST_TTL,
};
pub use paths::{DevicePathEntry, DevicePathError, DevicePathOperation, DevicePaths};
pub use process::{BrokerConnectionExit, BrokerProcess, BrokerProcessError};
pub use process_lock::{
    BrokerProcessLock, BrokerProcessLockError, BrokerProcessLockOperation, BrokerServiceRuntime,
    BrokerServiceStartupError,
};
pub use process_run::{
    BrokerProcessEnvironment, BrokerProcessRunCancellation, BrokerProcessRunError,
    BrokerProcessRunRequest, BrokerProcessRunResponse, MAX_PROCESS_ARGUMENTS,
    MAX_PROCESS_ARGUMENT_BYTES, MAX_PROCESS_ENVIRONMENT_BYTES, MAX_PROCESS_ENVIRONMENT_ENTRIES,
    MAX_PROCESS_ENVIRONMENT_NAME_BYTES, MAX_PROCESS_ENVIRONMENT_VALUE_BYTES,
    MAX_PROCESS_EXECUTABLE_BYTES, MAX_PROCESS_OUTPUT_BYTES, MAX_PROCESS_RUN_TIMEOUT,
    MAX_PROCESS_SECRET_BYTES, MAX_PROCESS_WORKING_DIRECTORY_BYTES, PROCESS_RUN_FILE_DESCRIPTOR,
};
pub use protocol::{
    decode_broker_request, decode_broker_response, encode_broker_request, encode_broker_response,
    read_broker_frame, write_broker_frame, BrokerAuthenticationChallengeResponse,
    BrokerAuthenticationCompleteRequest, BrokerAuthenticationResponse,
    BrokerAuthenticationStartRequest, BrokerCapabilitySet, BrokerCapabilityVersions,
    BrokerErrorCode, BrokerFrameError, BrokerHelloRequest, BrokerHelloResponse, BrokerInstanceId,
    BrokerNegotiatedCapability, BrokerPairingCompleteRequest, BrokerPairingCompleteResponse,
    BrokerPairingPendingResponse, BrokerPairingProgressResponse, BrokerPairingStartRequest,
    BrokerPairingStatusRequest, BrokerProtocolError, BrokerProtocolIdParseError,
    BrokerProtocolValidationError, BrokerProtocolVersion, BrokerProtocolVersionRange,
    BrokerRequest, BrokerRequestDecodeError, BrokerRequestEnvelope, BrokerRequestId,
    BrokerRequiredAction, BrokerResponse, BrokerResponseDecodeError, BrokerResponseEnvelope,
    BrokerSessionId, BrokerStatusResponse, BROKER_PROTOCOL_MAJOR, BROKER_PROTOCOL_MINOR,
    BROKER_PROTOCOL_NAME, MAX_BROKER_FRAME_LENGTH, MAX_BROKER_HELLO_LENGTH,
};
pub use psw_core::{CredentialId, SecretFieldId, SecretFieldKind, VaultId};
pub use readiness::{
    BrokerProtectedStateCategory, BrokerReadinessError, BrokerReadinessProjection,
};
pub use revocation::{BrokerRevocationError, BrokerRevocationKind, BrokerRevocationSummary};
pub use runtime::{BrokerRuntime, BrokerRuntimeError};
pub use state_model::{
    AccessRule, AccessRuleId, ApprovalKind, ApprovalRequest, ApprovalRequestId, ApprovalStatus,
    ApprovalSubject, AuditDecision, AuditEvent, AuditEventId, AuditEventKind, AuditScope,
    AuthorizationTarget, Capability, CapabilityName, ConfirmationMethod, ConfirmationPolicy,
    Consumer, ConsumerCodeSigningEvidence, ConsumerEvidenceFingerprint, ConsumerId,
    CredentialFieldScope, DeviceStateValidationError, DeviceStateValueParseError, GrantScope,
    LocalIdParseError, ObservedConsumerIdentity, PairingRequestId, RuleLifetime, StateTimestamp,
    UsagePlacement, UsageProfile, UsageProfileDefinition, UsageProfileId, UseGrant, UseGrantId,
    VaultSessionId, CURRENT_USAGE_PROFILE_DEFINITION_VERSION, MAX_USAGE_PROFILE_DEFINITION_BYTES,
};
pub use state_store::{
    DeviceStateDatabaseErrorCategory, DeviceStateDatabaseOperation, DeviceStateError,
    DeviceStateFileEntry, DeviceStateFileOperation, DeviceStateRemoval, DeviceStateStore,
    FieldAuthorizationRemoval, SqlCipherVersion, DEFAULT_AUDIT_RETENTION_DAYS,
    DEVICE_STATE_DATABASE_FILENAME, DEVICE_STATE_SQLCIPHER_MAJOR, MAX_AUDIT_RETENTION_DAYS,
    MAX_RETAINED_AUDIT_EVENTS, MIN_AUDIT_RETENTION_DAYS,
};
#[cfg(target_os = "macos")]
pub use unix_transport::{
    UnixBrokerConnection, UnixBrokerListener, UnixBrokerPeerIdentity, UnixBrokerTransportEntry,
    UnixBrokerTransportError, UnixBrokerTransportOperation, BROKER_SOCKET_FILENAME,
};
pub use usage_profile::BrokerUsageProfileError;
pub use usage_profile_template::{
    bundled_usage_profile_template, bundled_usage_profile_templates,
    recommend_bundled_usage_profile, BundledUsageProfileRecommendation,
    BundledUsageProfileRecommendationId, BundledUsageProfileTemplate,
    BundledUsageProfileTemplateId, BundledUsageProfileTemplateIdParseError,
    UsageProfileTemplateTechnicalField, BUNDLED_USAGE_PROFILE_TEMPLATES,
};
pub use use_grant::{
    BrokerAllowOnceApproval, BrokerAuthorizedGrantUse, BrokerConsumerUseGrantStatus,
    BrokerRuleUseApproval, BrokerUseGrantBasis, BrokerUseGrantError, BrokerUseGrantIssuance,
};
pub use vault_session::{
    BrokerVaultLockEvent, BrokerVaultLockReason, BrokerVaultLockState, BrokerVaultSessionError,
    BrokerVaultSessionManager, BrokerVaultSessionOperation, BrokerVaultSessionSnapshot,
    DEFAULT_BROKER_AUTO_LOCK_TIMEOUT,
};
