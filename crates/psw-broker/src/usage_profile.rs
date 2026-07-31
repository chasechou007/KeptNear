use std::fmt::{Display, Formatter};

use crate::state_model::{
    Capability, ConsumerId, DeviceStateValidationError, StateTimestamp, UsageProfile,
    UsageProfileDefinition, UsageProfileId,
};
use crate::state_store::{DeviceStateError, DeviceStateStore};

/// Failure while managing Consumer-owned Usage Profiles.
#[derive(Debug)]
pub enum BrokerUsageProfileError {
    /// The paired Consumer does not exist.
    ConsumerUnavailable,
    /// The profile label or declarative definition is invalid.
    Validation(DeviceStateValidationError),
    /// No exact Usage Profile belongs to the requesting Consumer.
    ProfileUnavailable,
    /// The Usage Profile capability does not match the requested operation.
    CapabilityMismatch,
    /// Encrypted device-local state could not be read or changed.
    DeviceState(DeviceStateError),
}

impl Display for BrokerUsageProfileError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConsumerUnavailable => formatter.write_str("Usage Profile Consumer unavailable"),
            Self::Validation(source) => {
                write!(formatter, "Usage Profile validation failed: {source}")
            }
            Self::ProfileUnavailable => formatter.write_str("Usage Profile unavailable"),
            Self::CapabilityMismatch => {
                formatter.write_str("Usage Profile capability does not match")
            }
            Self::DeviceState(source) => write!(formatter, "Usage Profile state failed: {source}"),
        }
    }
}

impl std::error::Error for BrokerUsageProfileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConsumerUnavailable | Self::ProfileUnavailable | Self::CapabilityMismatch => None,
            Self::Validation(source) => Some(source),
            Self::DeviceState(source) => Some(source),
        }
    }
}

impl From<DeviceStateError> for BrokerUsageProfileError {
    fn from(source: DeviceStateError) -> Self {
        Self::DeviceState(source)
    }
}

impl From<DeviceStateValidationError> for BrokerUsageProfileError {
    fn from(source: DeviceStateValidationError) -> Self {
        Self::Validation(source)
    }
}

pub(crate) struct BrokerUsageProfileManager;

impl BrokerUsageProfileManager {
    pub(crate) fn create(
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
        label: String,
        definition: UsageProfileDefinition,
        created_at: StateTimestamp,
    ) -> Result<UsageProfile, BrokerUsageProfileError> {
        if state.consumer(consumer_id)?.is_none() {
            return Err(BrokerUsageProfileError::ConsumerUnavailable);
        }
        let profile = UsageProfile::from_definition(consumer_id, label, definition, created_at)?;
        state.insert_usage_profile(&profile)?;
        Ok(profile)
    }

    pub(crate) fn remove(
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
        usage_profile_id: UsageProfileId,
    ) -> Result<bool, BrokerUsageProfileError> {
        if state.consumer(consumer_id)?.is_none() {
            return Err(BrokerUsageProfileError::ConsumerUnavailable);
        }
        let belongs_to_consumer = state
            .usage_profiles_for_consumer(consumer_id)?
            .iter()
            .any(|profile| profile.usage_profile_id() == usage_profile_id);
        if !belongs_to_consumer {
            return Ok(false);
        }
        state
            .remove_usage_profile(usage_profile_id)
            .map_err(BrokerUsageProfileError::from)
    }

    pub(crate) fn resolve_for_operation(
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
        usage_profile_id: UsageProfileId,
        capability: Capability,
    ) -> Result<UsageProfile, BrokerUsageProfileError> {
        if state.consumer(consumer_id)?.is_none() {
            return Err(BrokerUsageProfileError::ConsumerUnavailable);
        }
        let profile = state
            .usage_profiles_for_consumer(consumer_id)?
            .into_iter()
            .find(|profile| profile.usage_profile_id() == usage_profile_id)
            .ok_or(BrokerUsageProfileError::ProfileUnavailable)?;
        if profile.capability() != capability {
            return Err(BrokerUsageProfileError::CapabilityMismatch);
        }
        Ok(profile)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::device_key::DeviceRootKey;
    use crate::state_model::{
        Capability, CapabilityName, Consumer, ObservedConsumerIdentity, UsagePlacement,
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestState {
        path: PathBuf,
        store: DeviceStateStore,
    }

    impl TestState {
        fn new() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "keptnear-usage-profile-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create state directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protect state directory");
            let key = DeviceRootKey::from_stored_bytes(vec![91_u8; 32]).expect("root key");
            let store = DeviceStateStore::initialize_for_tests(&path, &key, timestamp(1))
                .expect("initialize state");
            Self { path, store }
        }
    }

    impl Drop for TestState {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn timestamp(value: i64) -> StateTimestamp {
        StateTimestamp::from_unix_millis(value).expect("timestamp")
    }

    fn consumer(key_byte: u8, label: &str) -> Consumer {
        Consumer::new(
            [key_byte; 32],
            label.to_owned(),
            ObservedConsumerIdentity::default(),
            timestamp(i64::from(key_byte)),
        )
        .expect("Consumer")
    }

    fn definition(variable_name: &str) -> UsageProfileDefinition {
        UsageProfileDefinition::new(
            Capability::v1(CapabilityName::ProcessRun),
            UsagePlacement::ProcessEnvironment {
                variable_name: variable_name.to_owned(),
            },
        )
        .expect("definition")
    }

    #[test]
    fn create_requires_an_existing_consumer_and_valid_profile() {
        let state = TestState::new();
        let missing_consumer = ConsumerId::generate();
        assert!(matches!(
            BrokerUsageProfileManager::create(
                &state.store,
                missing_consumer,
                "CLI token".to_owned(),
                definition("TOOL_TOKEN"),
                timestamp(10),
            ),
            Err(BrokerUsageProfileError::ConsumerUnavailable)
        ));

        let existing = consumer(92, "Local CLI");
        state
            .store
            .insert_consumer(&existing)
            .expect("insert Consumer");
        assert!(matches!(
            BrokerUsageProfileManager::create(
                &state.store,
                existing.consumer_id(),
                " ".to_owned(),
                definition("TOOL_TOKEN"),
                timestamp(11),
            ),
            Err(BrokerUsageProfileError::Validation(_))
        ));
    }

    #[test]
    fn removal_is_idempotent_and_cannot_cross_consumer_ownership() {
        let state = TestState::new();
        let first = consumer(93, "First CLI");
        let second = consumer(94, "Second CLI");
        state.store.insert_consumer(&first).expect("first Consumer");
        state
            .store
            .insert_consumer(&second)
            .expect("second Consumer");
        let profile = BrokerUsageProfileManager::create(
            &state.store,
            first.consumer_id(),
            "First token".to_owned(),
            definition("FIRST_TOKEN"),
            timestamp(20),
        )
        .expect("create profile");

        assert!(!BrokerUsageProfileManager::remove(
            &state.store,
            second.consumer_id(),
            profile.usage_profile_id(),
        )
        .expect("cross-Consumer remove"));
        assert_eq!(
            state
                .store
                .usage_profiles_for_consumer(first.consumer_id())
                .expect("retained profile"),
            vec![profile.clone()]
        );
        assert!(BrokerUsageProfileManager::remove(
            &state.store,
            first.consumer_id(),
            profile.usage_profile_id(),
        )
        .expect("remove profile"));
        assert!(!BrokerUsageProfileManager::remove(
            &state.store,
            first.consumer_id(),
            profile.usage_profile_id(),
        )
        .expect("repeat removal"));
    }

    #[test]
    fn operation_resolution_requires_exact_owner_profile_and_capability() {
        let state = TestState::new();
        let first = consumer(95, "First API");
        let second = consumer(96, "Second API");
        state.store.insert_consumer(&first).expect("first Consumer");
        state
            .store
            .insert_consumer(&second)
            .expect("second Consumer");
        let http_capability = Capability::v1(CapabilityName::HttpRequest);
        let profile = BrokerUsageProfileManager::create(
            &state.store,
            first.consumer_id(),
            "Bearer token".to_owned(),
            UsageProfileDefinition::new(
                http_capability,
                UsagePlacement::HttpBearerAuthorization {},
            )
            .expect("definition"),
            timestamp(30),
        )
        .expect("create profile");

        assert_eq!(
            BrokerUsageProfileManager::resolve_for_operation(
                &state.store,
                first.consumer_id(),
                profile.usage_profile_id(),
                http_capability,
            )
            .expect("resolve"),
            profile
        );
        assert!(matches!(
            BrokerUsageProfileManager::resolve_for_operation(
                &state.store,
                second.consumer_id(),
                profile.usage_profile_id(),
                http_capability,
            ),
            Err(BrokerUsageProfileError::ProfileUnavailable)
        ));
        assert!(matches!(
            BrokerUsageProfileManager::resolve_for_operation(
                &state.store,
                first.consumer_id(),
                profile.usage_profile_id(),
                Capability::v1(CapabilityName::ProcessRun),
            ),
            Err(BrokerUsageProfileError::CapabilityMismatch)
        ));
    }
}
