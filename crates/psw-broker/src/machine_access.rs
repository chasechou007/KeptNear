use std::fmt::{Debug, Display, Formatter};
use std::sync::{Mutex, MutexGuard};

use crate::protocol::BrokerErrorCode;
use crate::state_model::StateTimestamp;
use crate::state_store::{DeviceStateError, DeviceStateStore};

/// Result of an idempotent Apps & Tools pause-state change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerMachineAccessTransition {
    /// The requested state already applied and no write was needed.
    Unchanged,
    /// New machine credential operations are now denied.
    Paused,
    /// New machine credential operations may proceed to normal authorization.
    Resumed,
}

/// Sanitized failure at the device-wide machine-access gate.
#[derive(Debug)]
pub enum BrokerMachineAccessError {
    /// Apps & Tools access is intentionally paused.
    Paused,
    /// Authenticated encrypted pause state could not be read or persisted.
    DeviceState(DeviceStateError),
    /// Process-local gate state is unavailable after synchronization failure.
    StateUnavailable,
}

impl BrokerMachineAccessError {
    /// Returns the stable protocol error for a machine request.
    #[must_use]
    pub const fn broker_error_code(&self) -> BrokerErrorCode {
        match self {
            Self::Paused => BrokerErrorCode::BrokerPaused,
            Self::DeviceState(_) | Self::StateUnavailable => BrokerErrorCode::OperationFailed,
        }
    }
}

impl Display for BrokerMachineAccessError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Paused => formatter.write_str("Apps & Tools access is paused"),
            Self::DeviceState(source) => {
                write!(formatter, "Apps & Tools pause state failed: {source}")
            }
            Self::StateUnavailable => {
                formatter.write_str("Apps & Tools pause state is unavailable")
            }
        }
    }
}

impl std::error::Error for BrokerMachineAccessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DeviceState(source) => Some(source),
            Self::Paused | Self::StateUnavailable => None,
        }
    }
}

impl From<DeviceStateError> for BrokerMachineAccessError {
    fn from(source: DeviceStateError) -> Self {
        Self::DeviceState(source)
    }
}

/// Process-local gate for every machine credential operation.
///
/// Human vault workflows do not pass through this gate. Pairing,
/// authorization, grant validation, and vault unlock remain separate checks
/// after this gate allows a machine operation.
pub struct BrokerMachineAccessGate {
    paused: Mutex<bool>,
}

impl BrokerMachineAccessGate {
    /// Loads the authenticated persisted pause state during Broker startup.
    pub fn from_device_state(state: &DeviceStateStore) -> Result<Self, BrokerMachineAccessError> {
        Ok(Self::from_paused(state.apps_tools_paused()?))
    }

    /// Returns the current device-wide Apps & Tools pause state.
    pub fn is_paused(&self) -> Result<bool, BrokerMachineAccessError> {
        Ok(*self.lock_state()?)
    }

    /// Rejects a new machine operation while global access is paused.
    ///
    /// Call this before authorization or grant consumption. Operations that
    /// passed the gate before pause began are not retroactively cancelled.
    pub fn authorize_machine_operation(&self) -> Result<(), BrokerMachineAccessError> {
        if *self.lock_state()? {
            return Err(BrokerMachineAccessError::Paused);
        }
        Ok(())
    }

    /// Atomically persists and applies a global pause or resume transition.
    ///
    /// The process-local mutex remains held across the encrypted-state write,
    /// so a concurrent new machine operation observes either the complete old
    /// state or the complete new state. Failed writes leave the prior state
    /// active.
    pub fn set_paused(
        &self,
        state: &DeviceStateStore,
        paused: bool,
        updated_at: StateTimestamp,
    ) -> Result<BrokerMachineAccessTransition, BrokerMachineAccessError> {
        self.set_paused_with(paused, || state.set_apps_tools_paused(paused, updated_at))
    }

    fn from_paused(paused: bool) -> Self {
        Self {
            paused: Mutex::new(paused),
        }
    }

    fn set_paused_with(
        &self,
        paused: bool,
        persist: impl FnOnce() -> Result<(), DeviceStateError>,
    ) -> Result<BrokerMachineAccessTransition, BrokerMachineAccessError> {
        let mut current = self.lock_state()?;
        if *current == paused {
            return Ok(BrokerMachineAccessTransition::Unchanged);
        }
        persist()?;
        *current = paused;
        Ok(if paused {
            BrokerMachineAccessTransition::Paused
        } else {
            BrokerMachineAccessTransition::Resumed
        })
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, bool>, BrokerMachineAccessError> {
        self.paused
            .lock()
            .map_err(|_| BrokerMachineAccessError::StateUnavailable)
    }
}

impl Debug for BrokerMachineAccessGate {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerMachineAccessGate")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::state_store::{DeviceStateDatabaseErrorCategory, DeviceStateDatabaseOperation};

    #[test]
    fn paused_gate_uses_stable_protocol_error_and_resume_restores_access() {
        let gate = BrokerMachineAccessGate::from_paused(true);
        let paused = gate
            .authorize_machine_operation()
            .expect_err("paused machine operation");
        assert!(matches!(paused, BrokerMachineAccessError::Paused));
        assert_eq!(paused.broker_error_code(), BrokerErrorCode::BrokerPaused);

        assert_eq!(
            gate.set_paused_with(false, || Ok(()))
                .expect("resume transition"),
            BrokerMachineAccessTransition::Resumed
        );
        gate.authorize_machine_operation().expect("resumed access");
    }

    #[test]
    fn failed_persistence_keeps_prior_state_and_maps_to_operation_failed() {
        let gate = BrokerMachineAccessGate::from_paused(false);
        let error = gate
            .set_paused_with(true, || {
                Err(DeviceStateError::Database {
                    operation: DeviceStateDatabaseOperation::Write,
                    category: DeviceStateDatabaseErrorCategory::Busy,
                })
            })
            .expect_err("reject failed persistence");
        assert!(matches!(error, BrokerMachineAccessError::DeviceState(_)));
        assert_eq!(error.broker_error_code(), BrokerErrorCode::OperationFailed);
        assert!(!gate.is_paused().expect("unchanged state"));
        gate.authorize_machine_operation()
            .expect("prior access remains");
    }

    #[test]
    fn idempotent_transition_does_not_write_device_state() {
        let gate = BrokerMachineAccessGate::from_paused(true);
        let writes = AtomicUsize::new(0);
        assert_eq!(
            gate.set_paused_with(true, || {
                writes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .expect("idempotent pause"),
            BrokerMachineAccessTransition::Unchanged
        );
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn new_machine_check_waits_for_pause_persistence_then_fails_closed() {
        let gate = Arc::new(BrokerMachineAccessGate::from_paused(false));
        let persistence_started = Arc::new(Barrier::new(2));
        let release_persistence = Arc::new(Barrier::new(2));
        let pause_gate = Arc::clone(&gate);
        let pause_started = Arc::clone(&persistence_started);
        let pause_release = Arc::clone(&release_persistence);
        let pause_thread = thread::spawn(move || {
            pause_gate.set_paused_with(true, || {
                pause_started.wait();
                pause_release.wait();
                Ok(())
            })
        });
        persistence_started.wait();

        let check_gate = Arc::clone(&gate);
        let (attempted_tx, attempted_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let check_thread = thread::spawn(move || {
            attempted_tx.send(()).expect("attempt signal");
            result_tx
                .send(check_gate.authorize_machine_operation())
                .expect("result");
        });
        attempted_rx.recv().expect("check attempted");
        assert!(result_rx.recv_timeout(Duration::from_millis(30)).is_err());

        release_persistence.wait();
        assert_eq!(
            pause_thread.join().expect("pause thread").expect("pause"),
            BrokerMachineAccessTransition::Paused
        );
        assert!(matches!(
            result_rx.recv().expect("check result"),
            Err(BrokerMachineAccessError::Paused)
        ));
        check_thread.join().expect("check thread");
    }
}
