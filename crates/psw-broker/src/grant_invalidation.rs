use std::fmt::{Display, Formatter};

use crate::state_model::{ConsumerId, CredentialFieldScope};
use crate::state_store::{DeviceStateError, DeviceStateStore, FieldAuthorizationRemoval};
use crate::vault_session::{BrokerVaultSessionError, BrokerVaultSessionManager};

/// Sanitized failure while synchronizing session and authorization lifecycle.
#[derive(Debug)]
pub enum BrokerGrantInvalidationError {
    /// The process-owned vault-session lifecycle could not be read or changed.
    VaultSession(BrokerVaultSessionError),
    /// Authenticated encrypted device state could not be changed.
    DeviceState(DeviceStateError),
}

impl Display for BrokerGrantInvalidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VaultSession(source) => {
                write!(
                    formatter,
                    "vault-session grant invalidation failed: {source}"
                )
            }
            Self::DeviceState(source) => {
                write!(
                    formatter,
                    "device-state grant invalidation failed: {source}"
                )
            }
        }
    }
}

impl std::error::Error for BrokerGrantInvalidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::VaultSession(source) => Some(source),
            Self::DeviceState(source) => Some(source),
        }
    }
}

impl From<BrokerVaultSessionError> for BrokerGrantInvalidationError {
    fn from(source: BrokerVaultSessionError) -> Self {
        Self::VaultSession(source)
    }
}

impl From<DeviceStateError> for BrokerGrantInvalidationError {
    fn from(source: DeviceStateError) -> Self {
        Self::DeviceState(source)
    }
}

/// Non-secret result of applying queued vault-lock events to Use Grants.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BrokerGrantInvalidationSummary {
    lock_events_processed: usize,
    use_grants_removed: usize,
    invalidated_all_use_grants: bool,
}

impl BrokerGrantInvalidationSummary {
    /// Returns the number of ended vault sessions in the acknowledged batch.
    #[must_use]
    pub const fn lock_events_processed(self) -> usize {
        self.lock_events_processed
    }

    /// Returns the number of persisted Use Grants removed.
    #[must_use]
    pub const fn use_grants_removed(self) -> usize {
        self.use_grants_removed
    }

    /// Returns whether queue overflow or device reset required deleting all grants.
    #[must_use]
    pub const fn invalidated_all_use_grants(self) -> bool {
        self.invalidated_all_use_grants
    }
}

/// Connects vault-session endings to authenticated device-state revocation.
pub struct BrokerGrantInvalidator;

impl BrokerGrantInvalidator {
    /// Removes every grant left by an earlier Broker process before startup.
    ///
    /// Vault sessions are process-owned and never survive restart, so no
    /// persisted grant can remain eligible in a newly created process.
    pub fn invalidate_stale_grants_on_startup(
        state: &mut DeviceStateStore,
    ) -> Result<usize, BrokerGrantInvalidationError> {
        state.invalidate_all_use_grants().map_err(Into::into)
    }

    /// Applies every pending lock, close, timeout, and shutdown event.
    ///
    /// Events are acknowledged only after the SQLCipher transaction commits.
    /// If the bounded queue overflowed, every Use Grant is removed rather than
    /// trusting an incomplete event list.
    pub fn synchronize_lock_events(
        sessions: &BrokerVaultSessionManager,
        state: &mut DeviceStateStore,
    ) -> Result<BrokerGrantInvalidationSummary, BrokerGrantInvalidationError> {
        let checkpoint = sessions.lock_event_checkpoint()?;
        let lock_events_processed = checkpoint.events().len();
        let invalidated_all_use_grants = checkpoint.overflowed();
        if lock_events_processed == 0 && !invalidated_all_use_grants {
            return Ok(BrokerGrantInvalidationSummary::default());
        }

        let use_grants_removed = if invalidated_all_use_grants {
            state.invalidate_all_use_grants()?
        } else {
            let ended_sessions = checkpoint
                .events()
                .iter()
                .map(|event| (event.vault_id(), event.vault_session_id()))
                .collect::<Vec<_>>();
            state.invalidate_use_grants_for_sessions(&ended_sessions)?
        };
        sessions.acknowledge_lock_event_checkpoint(checkpoint)?;
        Ok(BrokerGrantInvalidationSummary {
            lock_events_processed,
            use_grants_removed,
            invalidated_all_use_grants,
        })
    }

    /// Removes one Consumer and its cascading rules, grants, profiles, and approvals.
    pub fn remove_consumer(
        state: &mut DeviceStateStore,
        consumer_id: ConsumerId,
    ) -> Result<bool, BrokerGrantInvalidationError> {
        state.remove_consumer(consumer_id).map_err(Into::into)
    }

    /// Removes rules, grants, and approvals for one deleted credential field.
    pub fn remove_field_authorization(
        state: &mut DeviceStateStore,
        field_scope: CredentialFieldScope,
    ) -> Result<FieldAuthorizationRemoval, BrokerGrantInvalidationError> {
        state
            .remove_field_authorization(field_scope)
            .map_err(Into::into)
    }

    /// Locks all vault sessions and clears grants before device-state reset.
    ///
    /// The later reset workflow owns database and Keychain deletion. It must
    /// not begin those destructive steps unless this preparation succeeds.
    pub fn prepare_device_data_reset(
        sessions: &BrokerVaultSessionManager,
        state: &mut DeviceStateStore,
    ) -> Result<BrokerGrantInvalidationSummary, BrokerGrantInvalidationError> {
        Self::prepare_process_shutdown(sessions, state)
    }

    /// Shuts down process-owned sessions and removes every persisted grant.
    pub fn prepare_process_shutdown(
        sessions: &BrokerVaultSessionManager,
        state: &mut DeviceStateStore,
    ) -> Result<BrokerGrantInvalidationSummary, BrokerGrantInvalidationError> {
        sessions.shutdown()?;
        let checkpoint = sessions.lock_event_checkpoint()?;
        let lock_events_processed = checkpoint.events().len();
        let use_grants_removed = state.invalidate_all_use_grants()?;
        sessions.acknowledge_lock_event_checkpoint(checkpoint)?;
        Ok(BrokerGrantInvalidationSummary {
            lock_events_processed,
            use_grants_removed,
            invalidated_all_use_grants: true,
        })
    }
}
