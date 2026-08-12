use std::fmt::{Debug, Display, Formatter};

use psw_core::VaultId;
use serde::Serialize;

use crate::state_model::{
    AuditDecision, AuditEvent, AuditEventId, AuditEventKind, Capability, ConsumerId,
    CredentialFieldScope, StateTimestamp,
};
use crate::state_store::{DeviceStateError, DeviceStateStore, MAX_RETAINED_AUDIT_EVENTS};
use crate::HumanControlAuditConfirmationId;

/// Maximum number of audit events returned by one trusted local view request.
pub const MAX_AUDIT_VIEW_EVENTS: usize = 500;

/// Exact, non-secret filters accepted by the local audit control plane.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BrokerAuditFilter {
    event_kind: Option<AuditEventKind>,
    decision: Option<AuditDecision>,
    consumer_id: Option<ConsumerId>,
    vault_id: Option<VaultId>,
    field_scope: Option<CredentialFieldScope>,
    capability: Option<Capability>,
    occurred_at_or_after: Option<StateTimestamp>,
    occurred_before: Option<StateTimestamp>,
}

impl BrokerAuditFilter {
    /// Creates an unfiltered local audit selection.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            event_kind: None,
            decision: None,
            consumer_id: None,
            vault_id: None,
            field_scope: None,
            capability: None,
            occurred_at_or_after: None,
            occurred_before: None,
        }
    }

    /// Restricts the selection to one event category.
    #[must_use]
    pub const fn with_event_kind(mut self, event_kind: AuditEventKind) -> Self {
        self.event_kind = Some(event_kind);
        self
    }

    /// Restricts the selection to one decision.
    #[must_use]
    pub const fn with_decision(mut self, decision: AuditDecision) -> Self {
        self.decision = Some(decision);
        self
    }

    /// Restricts the selection to one immutable Consumer identity.
    #[must_use]
    pub const fn with_consumer(mut self, consumer_id: ConsumerId) -> Self {
        self.consumer_id = Some(consumer_id);
        self
    }

    /// Restricts the selection to one stable Vault identity.
    #[must_use]
    pub const fn with_vault(mut self, vault_id: VaultId) -> Self {
        self.vault_id = Some(vault_id);
        self
    }

    /// Restricts the selection to one exact stable Secret Field scope.
    #[must_use]
    pub const fn with_field_scope(mut self, field_scope: CredentialFieldScope) -> Self {
        self.field_scope = Some(field_scope);
        self
    }

    /// Restricts the selection to one exact capability name and version.
    #[must_use]
    pub const fn with_capability(mut self, capability: Capability) -> Self {
        self.capability = Some(capability);
        self
    }

    /// Restricts the selection to events at or after the supplied timestamp.
    #[must_use]
    pub const fn occurring_at_or_after(mut self, timestamp: StateTimestamp) -> Self {
        self.occurred_at_or_after = Some(timestamp);
        self
    }

    /// Restricts the selection to events strictly before the supplied timestamp.
    #[must_use]
    pub const fn occurring_before(mut self, timestamp: StateTimestamp) -> Self {
        self.occurred_before = Some(timestamp);
        self
    }

    pub(crate) const fn event_kind(self) -> Option<AuditEventKind> {
        self.event_kind
    }

    pub(crate) const fn decision(self) -> Option<AuditDecision> {
        self.decision
    }

    pub(crate) const fn consumer_id(self) -> Option<ConsumerId> {
        self.consumer_id
    }

    pub(crate) const fn vault_id(self) -> Option<VaultId> {
        self.vault_id
    }

    pub(crate) const fn field_scope(self) -> Option<CredentialFieldScope> {
        self.field_scope
    }

    pub(crate) const fn capability(self) -> Option<Capability> {
        self.capability
    }

    pub(crate) const fn occurred_at_or_after(self) -> Option<StateTimestamp> {
        self.occurred_at_or_after
    }

    pub(crate) const fn occurred_before(self) -> Option<StateTimestamp> {
        self.occurred_before
    }

    fn validate(self) -> Result<(), BrokerAuditError> {
        if matches!(
            (self.occurred_at_or_after, self.occurred_before),
            (Some(start), Some(end)) if start >= end
        ) {
            return Err(BrokerAuditError::InvalidTimeWindow);
        }
        if matches!(
            (self.vault_id, self.field_scope),
            (Some(vault_id), Some(field_scope)) if vault_id != field_scope.vault_id()
        ) {
            return Err(BrokerAuditError::InconsistentScope);
        }
        Ok(())
    }
}

/// Stable continuation position for newest-first local audit pagination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerAuditCursor {
    occurred_at: StateTimestamp,
    audit_event_id: AuditEventId,
}

impl BrokerAuditCursor {
    /// Reconstructs one continuation cursor from a validated closed wire body.
    #[must_use]
    pub const fn from_validated_wire_bindings(
        occurred_at: StateTimestamp,
        audit_event_id: AuditEventId,
    ) -> Self {
        Self {
            occurred_at,
            audit_event_id,
        }
    }

    fn after(event: &AuditEvent) -> Self {
        Self::from_validated_wire_bindings(event.occurred_at(), event.audit_event_id())
    }

    pub(crate) const fn occurred_at(self) -> StateTimestamp {
        self.occurred_at
    }

    pub(crate) const fn audit_event_id(self) -> AuditEventId {
        self.audit_event_id
    }
}

/// One bounded newest-first page for the trusted local audit viewer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerAuditPage {
    events: Vec<AuditEvent>,
    next_cursor: Option<BrokerAuditCursor>,
}

impl BrokerAuditPage {
    /// Returns the events in newest-first stable order.
    #[must_use]
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// Returns a continuation cursor only when another matching page exists.
    #[must_use]
    pub const fn next_cursor(&self) -> Option<BrokerAuditCursor> {
        self.next_cursor
    }

    /// Consumes the page and returns its events.
    #[must_use]
    pub fn into_events(self) -> Vec<AuditEvent> {
        self.events
    }
}

/// Single-use exact-selection token retained by a trusted local control plane.
#[derive(Debug, Eq, PartialEq)]
pub struct BrokerAuditClearConfirmation {
    confirmation_id: HumanControlAuditConfirmationId,
    filter: BrokerAuditFilter,
}

impl BrokerAuditClearConfirmation {
    /// Records that the trusted local control plane confirmed one exact selection.
    #[must_use]
    pub fn after_user_confirmation(filter: BrokerAuditFilter) -> Self {
        Self::for_human_control_selection(filter)
    }

    /// Issues one token for a selection returned to the authenticated App.
    pub(crate) fn for_human_control_selection(filter: BrokerAuditFilter) -> Self {
        Self {
            confirmation_id: HumanControlAuditConfirmationId::generate(),
            filter,
        }
    }

    /// Returns the single-use identity shown with the confirmed selection.
    #[must_use]
    pub const fn confirmation_id(&self) -> HumanControlAuditConfirmationId {
        self.confirmation_id
    }

    pub(crate) fn matches(
        &self,
        confirmation_id: HumanControlAuditConfirmationId,
        filter: BrokerAuditFilter,
    ) -> bool {
        self.confirmation_id == confirmation_id && self.filter == filter
    }

    fn matches_filter(&self, filter: BrokerAuditFilter) -> bool {
        self.filter == filter
    }
}

/// Non-secret counts from one committed local audit clear operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerAuditClearSummary {
    removed_events: usize,
    remaining_events: usize,
}

impl BrokerAuditClearSummary {
    /// Returns the number of selected events removed.
    #[must_use]
    pub const fn removed_events(self) -> usize {
        self.removed_events
    }

    /// Returns the number of events remaining after the transaction.
    #[must_use]
    pub const fn remaining_events(self) -> usize {
        self.remaining_events
    }
}

/// Versioned non-secret JSON produced for explicit local troubleshooting.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerAuditExport {
    json: String,
    event_count: usize,
}

impl BrokerAuditExport {
    /// Returns the UTF-8 JSON document.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.json
    }

    /// Returns the UTF-8 JSON bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.json.as_bytes()
    }

    /// Returns the number of exported events.
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.event_count
    }
}

impl Debug for BrokerAuditExport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerAuditExport")
            .field("event_count", &self.event_count)
            .field("byte_length", &self.json.len())
            .finish_non_exhaustive()
    }
}

/// Sanitized failure from the trusted local audit control plane.
#[derive(Debug)]
pub enum BrokerAuditError {
    /// A view request exceeded its fixed page bound or requested zero events.
    InvalidViewLimit,
    /// The inclusive start was not earlier than the exclusive end.
    InvalidTimeWindow,
    /// A Vault filter disagreed with the exact field scope.
    InconsistentScope,
    /// The explicit confirmation was issued for another audit selection.
    ConfirmationMismatch,
    /// Authenticated encrypted device state could not be read or changed.
    DeviceState(DeviceStateError),
    /// The fixed non-secret JSON projection could not be encoded.
    Serialization,
    /// A bounded control-plane export exceeded its fixed byte budget.
    ExportTooLarge,
}

impl Display for BrokerAuditError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidViewLimit => formatter.write_str("audit view limit is invalid"),
            Self::InvalidTimeWindow => formatter.write_str("audit time window is invalid"),
            Self::InconsistentScope => formatter.write_str("audit scope is inconsistent"),
            Self::ConfirmationMismatch => {
                formatter.write_str("audit clear confirmation does not match the selection")
            }
            Self::DeviceState(source) => write!(formatter, "audit state failed: {source}"),
            Self::Serialization => formatter.write_str("audit export encoding failed"),
            Self::ExportTooLarge => formatter.write_str("audit export exceeds its fixed bound"),
        }
    }
}

impl std::error::Error for BrokerAuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DeviceState(source) => Some(source),
            Self::InvalidViewLimit
            | Self::InvalidTimeWindow
            | Self::InconsistentScope
            | Self::ConfirmationMismatch
            | Self::Serialization
            | Self::ExportTooLarge => None,
        }
    }
}

impl From<DeviceStateError> for BrokerAuditError {
    fn from(source: DeviceStateError) -> Self {
        Self::DeviceState(source)
    }
}

pub(crate) struct BrokerAuditManager;

impl BrokerAuditManager {
    pub(crate) fn view(
        state: &DeviceStateStore,
        filter: BrokerAuditFilter,
        cursor: Option<BrokerAuditCursor>,
        limit: usize,
        observed_at: StateTimestamp,
    ) -> Result<BrokerAuditPage, BrokerAuditError> {
        filter.validate()?;
        if limit == 0 || limit > MAX_AUDIT_VIEW_EVENTS {
            return Err(BrokerAuditError::InvalidViewLimit);
        }
        state.enforce_audit_retention(observed_at)?;
        Self::view_without_retention(state, filter, cursor, limit)
    }

    pub(crate) fn clear(
        state: &DeviceStateStore,
        filter: BrokerAuditFilter,
        confirmation: BrokerAuditClearConfirmation,
    ) -> Result<BrokerAuditClearSummary, BrokerAuditError> {
        filter.validate()?;
        if !confirmation.matches_filter(filter) {
            return Err(BrokerAuditError::ConfirmationMismatch);
        }
        let (removed_events, remaining_events) = state.clear_audit_events_matching(filter)?;
        Ok(BrokerAuditClearSummary {
            removed_events,
            remaining_events,
        })
    }

    pub(crate) fn export_json(
        state: &DeviceStateStore,
        filter: BrokerAuditFilter,
        generated_at: StateTimestamp,
    ) -> Result<BrokerAuditExport, BrokerAuditError> {
        filter.validate()?;
        state.enforce_audit_retention(generated_at)?;

        let mut events = Vec::new();
        let mut cursor = None;
        loop {
            let page = Self::view_without_retention(state, filter, cursor, MAX_AUDIT_VIEW_EVENTS)?;
            events.extend(page.events.iter().map(AuditExportEvent::from));
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
            if events.len() > MAX_RETAINED_AUDIT_EVENTS {
                return Err(BrokerAuditError::DeviceState(
                    DeviceStateError::CorruptRecord,
                ));
            }
        }

        Self::encode_export(events, generated_at, usize::MAX)
    }

    pub(crate) fn export_json_limited(
        state: &DeviceStateStore,
        filter: BrokerAuditFilter,
        generated_at: StateTimestamp,
        max_events: usize,
        max_bytes: usize,
    ) -> Result<BrokerAuditExport, BrokerAuditError> {
        filter.validate()?;
        if max_events == 0 || max_events > MAX_AUDIT_VIEW_EVENTS || max_bytes == 0 {
            return Err(BrokerAuditError::InvalidViewLimit);
        }
        state.enforce_audit_retention(generated_at)?;
        let page = Self::view_without_retention(state, filter, None, max_events)?;
        let events = page.events.iter().map(AuditExportEvent::from).collect();
        Self::encode_export(events, generated_at, max_bytes)
    }

    fn encode_export(
        events: Vec<AuditExportEvent>,
        generated_at: StateTimestamp,
        max_bytes: usize,
    ) -> Result<BrokerAuditExport, BrokerAuditError> {
        let document = AuditExportDocument {
            format: "keptnear-audit-export",
            version: 1,
            generated_at_ms: generated_at.unix_millis(),
            events,
        };
        let event_count = document.events.len();
        let mut json =
            serde_json::to_string_pretty(&document).map_err(|_| BrokerAuditError::Serialization)?;
        json.push('\n');
        if json.len() > max_bytes {
            return Err(BrokerAuditError::ExportTooLarge);
        }
        Ok(BrokerAuditExport { json, event_count })
    }

    fn view_without_retention(
        state: &DeviceStateStore,
        filter: BrokerAuditFilter,
        cursor: Option<BrokerAuditCursor>,
        limit: usize,
    ) -> Result<BrokerAuditPage, BrokerAuditError> {
        let mut events = state.filtered_audit_events(filter, cursor, limit + 1)?;
        let has_more = events.len() > limit;
        if has_more {
            events.truncate(limit);
        }
        let next_cursor = has_more
            .then(|| events.last().map(BrokerAuditCursor::after))
            .flatten();
        Ok(BrokerAuditPage {
            events,
            next_cursor,
        })
    }
}

#[derive(Serialize)]
struct AuditExportDocument {
    format: &'static str,
    version: u16,
    generated_at_ms: i64,
    events: Vec<AuditExportEvent>,
}

#[derive(Serialize)]
struct AuditExportEvent {
    audit_event_id: String,
    occurred_at_ms: i64,
    event_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    consumer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vault_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_field_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capability_name: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capability_version: Option<u16>,
    decision: &'static str,
    confirmation_method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    use_grant_id: Option<String>,
}

impl From<&AuditEvent> for AuditExportEvent {
    fn from(event: &AuditEvent) -> Self {
        let scope = event.scope();
        let field_scope = scope.field_scope();
        let capability = scope.capability();
        Self {
            audit_event_id: event.audit_event_id().to_string(),
            occurred_at_ms: event.occurred_at().unix_millis(),
            event_kind: event.kind().as_str(),
            consumer_id: scope.consumer_id().map(|value| value.to_string()),
            vault_id: field_scope.map(|value| value.vault_id().to_string()),
            credential_id: field_scope.map(|value| value.credential_id().to_string()),
            secret_field_id: field_scope.map(|value| value.secret_field_id().to_string()),
            capability_name: capability.map(|value| value.name().as_str()),
            capability_version: capability.map(Capability::version),
            decision: event.decision().as_str(),
            confirmation_method: event.confirmation_method().as_str(),
            use_grant_id: scope.use_grant_id().map(|value| value.to_string()),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use psw_core::{CredentialId, SecretFieldId};

    use super::*;
    use crate::device_key::{DeviceRootKey, DEVICE_ROOT_KEY_LENGTH};
    use crate::state_model::{
        AuditScope, CapabilityName, ConfirmationMethod, Consumer, ObservedConsumerIdentity,
        UseGrantId,
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestStateDirectory {
        path: PathBuf,
    }

    impl TestStateDirectory {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "keptnear-audit-{label}-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create state directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protect state directory");
            Self { path }
        }

        fn initialize(&self, key_byte: u8) -> DeviceStateStore {
            let key = DeviceRootKey::from_stored_bytes(vec![key_byte; DEVICE_ROOT_KEY_LENGTH])
                .expect("root key");
            DeviceStateStore::initialize_for_tests(&self.path, &key, timestamp(0))
                .expect("initialize state")
        }
    }

    impl Drop for TestStateDirectory {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn timestamp(value: i64) -> StateTimestamp {
        StateTimestamp::from_unix_millis(value).expect("timestamp")
    }

    fn field_scope(vault_id: VaultId) -> CredentialFieldScope {
        CredentialFieldScope::new(
            vault_id,
            CredentialId::generate(),
            SecretFieldId::generate(),
        )
    }

    fn scoped_event(
        occurred_at: i64,
        kind: AuditEventKind,
        decision: AuditDecision,
        consumer_id: ConsumerId,
        field_scope: CredentialFieldScope,
        capability: Capability,
    ) -> AuditEvent {
        AuditEvent::new(
            timestamp(occurred_at),
            kind,
            AuditScope::new(
                Some(consumer_id),
                Some(field_scope),
                Some(capability),
                Some(UseGrantId::generate()),
            ),
            decision,
            ConfirmationMethod::PersistentRule,
        )
    }

    #[test]
    fn view_filters_and_paginates_with_a_stable_newest_first_cursor() {
        let directory = TestStateDirectory::new("view");
        let state = directory.initialize(81);
        let first_consumer = ConsumerId::generate();
        let second_consumer = ConsumerId::generate();
        let vault_id = VaultId::generate();
        let field = field_scope(vault_id);
        let search = Capability::v1(CapabilityName::CredentialSearch);
        let process = Capability::v1(CapabilityName::ProcessRun);
        let oldest = scoped_event(
            100,
            AuditEventKind::Authorization,
            AuditDecision::Allowed,
            first_consumer,
            field,
            search,
        );
        let middle = scoped_event(
            200,
            AuditEventKind::Grant,
            AuditDecision::Denied,
            first_consumer,
            field,
            search,
        );
        let other_capability = scoped_event(
            250,
            AuditEventKind::CredentialUse,
            AuditDecision::Allowed,
            first_consumer,
            field,
            process,
        );
        let other_consumer = scoped_event(
            300,
            AuditEventKind::Authorization,
            AuditDecision::Denied,
            second_consumer,
            field,
            search,
        );
        for event in [&oldest, &middle, &other_capability, &other_consumer] {
            state.append_audit_event(event).expect("append event");
        }

        let filter = BrokerAuditFilter::all()
            .with_consumer(first_consumer)
            .with_vault(vault_id)
            .with_capability(search)
            .occurring_at_or_after(timestamp(100))
            .occurring_before(timestamp(300));
        let first_page =
            BrokerAuditManager::view(&state, filter, None, 1, timestamp(300)).expect("first page");
        assert_eq!(first_page.events(), std::slice::from_ref(&middle));
        let cursor = first_page.next_cursor().expect("continuation");

        let newly_arrived = scoped_event(
            275,
            AuditEventKind::Grant,
            AuditDecision::Allowed,
            first_consumer,
            field,
            search,
        );
        state
            .append_audit_event(&newly_arrived)
            .expect("append concurrent event");
        let second_page = BrokerAuditManager::view(&state, filter, Some(cursor), 1, timestamp(300))
            .expect("second page");
        assert_eq!(second_page.events(), std::slice::from_ref(&oldest));
        assert_eq!(second_page.next_cursor(), None);

        let refreshed =
            BrokerAuditManager::view(&state, filter, None, 3, timestamp(300)).expect("refresh");
        assert_eq!(refreshed.events(), &[newly_arrived, middle.clone(), oldest]);
        assert_eq!(refreshed.next_cursor(), None);

        let exact = BrokerAuditManager::view(
            &state,
            BrokerAuditFilter::all()
                .with_event_kind(AuditEventKind::Grant)
                .with_decision(AuditDecision::Denied)
                .with_consumer(first_consumer)
                .with_field_scope(field)
                .with_capability(search),
            None,
            10,
            timestamp(300),
        )
        .expect("exact filter");
        assert_eq!(exact.events(), std::slice::from_ref(&middle));
    }

    #[test]
    fn cursor_orders_equal_timestamps_by_stable_event_identity() {
        let directory = TestStateDirectory::new("equal-time-cursor");
        let state = directory.initialize(86);
        let consumer_id = ConsumerId::generate();
        let field = field_scope(VaultId::generate());
        let capability = Capability::v1(CapabilityName::CredentialSearch);
        let mut expected = vec![
            scoped_event(
                100,
                AuditEventKind::Authorization,
                AuditDecision::Allowed,
                consumer_id,
                field,
                capability,
            ),
            scoped_event(
                100,
                AuditEventKind::Authorization,
                AuditDecision::Denied,
                consumer_id,
                field,
                capability,
            ),
            scoped_event(
                100,
                AuditEventKind::Authorization,
                AuditDecision::Failed,
                consumer_id,
                field,
                capability,
            ),
        ];
        for event in &expected {
            state.append_audit_event(event).expect("append event");
        }
        expected.sort_by_key(|event| std::cmp::Reverse(event.audit_event_id()));

        let mut actual = Vec::new();
        let mut cursor = None;
        loop {
            let page = BrokerAuditManager::view(
                &state,
                BrokerAuditFilter::all(),
                cursor,
                1,
                timestamp(100),
            )
            .expect("page");
            actual.extend_from_slice(page.events());
            cursor = page.next_cursor();
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(actual, expected);

        let cursor = BrokerAuditCursor::from_validated_wire_bindings(
            expected[0].occurred_at(),
            expected[0].audit_event_id(),
        );
        assert_eq!(cursor.occurred_at(), expected[0].occurred_at());
        assert_eq!(cursor.audit_event_id(), expected[0].audit_event_id());
    }

    #[test]
    fn invalid_view_bounds_and_inconsistent_filters_fail_closed() {
        let directory = TestStateDirectory::new("invalid-filter");
        let state = directory.initialize(82);
        let first_vault = VaultId::generate();
        let second_vault = VaultId::generate();
        let field = field_scope(first_vault);

        assert!(matches!(
            BrokerAuditManager::view(&state, BrokerAuditFilter::all(), None, 0, timestamp(10)),
            Err(BrokerAuditError::InvalidViewLimit)
        ));
        assert!(matches!(
            BrokerAuditManager::view(
                &state,
                BrokerAuditFilter::all(),
                None,
                MAX_AUDIT_VIEW_EVENTS + 1,
                timestamp(10)
            ),
            Err(BrokerAuditError::InvalidViewLimit)
        ));
        assert!(matches!(
            BrokerAuditManager::view(
                &state,
                BrokerAuditFilter::all()
                    .occurring_at_or_after(timestamp(10))
                    .occurring_before(timestamp(10)),
                None,
                1,
                timestamp(10)
            ),
            Err(BrokerAuditError::InvalidTimeWindow)
        ));
        assert!(matches!(
            BrokerAuditManager::view(
                &state,
                BrokerAuditFilter::all()
                    .with_vault(second_vault)
                    .with_field_scope(field),
                None,
                1,
                timestamp(10)
            ),
            Err(BrokerAuditError::InconsistentScope)
        ));
        assert!(state.recent_audit_events(1).expect("unchanged").is_empty());
    }

    #[test]
    fn confirmed_clear_removes_only_the_exact_filtered_selection() {
        let directory = TestStateDirectory::new("clear");
        let state = directory.initialize(83);
        let first_consumer = ConsumerId::generate();
        let second_consumer = ConsumerId::generate();
        let field = field_scope(VaultId::generate());
        let capability = Capability::v1(CapabilityName::HttpRequest);
        let selected = scoped_event(
            100,
            AuditEventKind::CredentialUse,
            AuditDecision::Allowed,
            first_consumer,
            field,
            capability,
        );
        let different_kind = scoped_event(
            110,
            AuditEventKind::Grant,
            AuditDecision::Allowed,
            first_consumer,
            field,
            capability,
        );
        let different_consumer = scoped_event(
            120,
            AuditEventKind::CredentialUse,
            AuditDecision::Allowed,
            second_consumer,
            field,
            capability,
        );
        for event in [&selected, &different_kind, &different_consumer] {
            state.append_audit_event(event).expect("append event");
        }

        let filter = BrokerAuditFilter::all()
            .with_consumer(first_consumer)
            .with_event_kind(AuditEventKind::CredentialUse);
        let mismatched_confirmation = BrokerAuditClearConfirmation::after_user_confirmation(filter);
        assert!(matches!(
            BrokerAuditManager::clear(
                &state,
                BrokerAuditFilter::all().with_consumer(second_consumer),
                mismatched_confirmation,
            ),
            Err(BrokerAuditError::ConfirmationMismatch)
        ));
        assert_eq!(state.recent_audit_events(10).expect("preserved").len(), 3);

        let confirmation = BrokerAuditClearConfirmation::after_user_confirmation(filter);
        let summary =
            BrokerAuditManager::clear(&state, filter, confirmation).expect("clear selection");

        assert_eq!(summary.removed_events(), 1);
        assert_eq!(summary.remaining_events(), 2);
        assert_eq!(
            state.recent_audit_events(10).expect("remaining"),
            vec![different_consumer, different_kind]
        );
    }

    #[test]
    fn export_is_versioned_and_contains_only_fixed_non_secret_fields() {
        let directory = TestStateDirectory::new("export");
        let state = directory.initialize(84);
        let private_marker = "KN_PRIVATE_LABEL_34f801";
        let consumer = Consumer::new(
            [85; 32],
            private_marker.to_owned(),
            ObservedConsumerIdentity::new(
                Some("private-executable-marker".to_owned()),
                None,
                None,
                None,
            )
            .expect("observed identity"),
            timestamp(10),
        )
        .expect("Consumer");
        state.insert_consumer(&consumer).expect("insert Consumer");
        let field = field_scope(VaultId::generate());
        let event = scoped_event(
            20,
            AuditEventKind::CredentialUse,
            AuditDecision::Allowed,
            consumer.consumer_id(),
            field,
            Capability::v1(CapabilityName::ProcessRun),
        );
        state.append_audit_event(&event).expect("append event");

        let export =
            BrokerAuditManager::export_json(&state, BrokerAuditFilter::all(), timestamp(30))
                .expect("export");
        assert_eq!(export.event_count(), 1);
        assert!(export.as_str().ends_with('\n'));
        assert!(!export.as_str().contains(private_marker));
        assert!(!export.as_str().contains("private-executable-marker"));
        assert!(!format!("{export:?}").contains(&event.audit_event_id().to_string()));

        let document: serde_json::Value =
            serde_json::from_slice(export.as_bytes()).expect("parse export");
        assert_eq!(document["format"], "keptnear-audit-export");
        assert_eq!(document["version"], 1);
        assert_eq!(document["generated_at_ms"], 30);
        let events = document["events"].as_array().expect("events");
        assert_eq!(events.len(), 1);
        let keys = events[0]
            .as_object()
            .expect("event")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            keys,
            BTreeSet::from([
                "audit_event_id",
                "occurred_at_ms",
                "event_kind",
                "consumer_id",
                "vault_id",
                "credential_id",
                "secret_field_id",
                "capability_name",
                "capability_version",
                "decision",
                "confirmation_method",
                "use_grant_id",
            ])
        );
        assert_eq!(
            events[0]["audit_event_id"],
            event.audit_event_id().to_string()
        );
    }

    #[test]
    fn limited_export_caps_event_count_and_encoded_bytes() {
        let directory = TestStateDirectory::new("bounded-export");
        let state = directory.initialize(87);
        let consumer_id = ConsumerId::generate();
        let field = field_scope(VaultId::generate());
        let capability = Capability::v1(CapabilityName::CredentialSearch);
        for occurred_at in 1..=300 {
            state
                .append_audit_event(&scoped_event(
                    occurred_at,
                    AuditEventKind::Authorization,
                    AuditDecision::Allowed,
                    consumer_id,
                    field,
                    capability,
                ))
                .expect("append event");
        }

        let export = BrokerAuditManager::export_json_limited(
            &state,
            BrokerAuditFilter::all(),
            timestamp(301),
            crate::MAX_HUMAN_CONTROL_AUDIT_EVENTS,
            crate::MAX_HUMAN_CONTROL_RESPONSE_LENGTH / 2,
        )
        .expect("bounded export");
        assert_eq!(export.event_count(), crate::MAX_HUMAN_CONTROL_AUDIT_EVENTS);
        assert!(export.as_bytes().len() <= crate::MAX_HUMAN_CONTROL_RESPONSE_LENGTH / 2);
        assert!(matches!(
            BrokerAuditManager::export_json_limited(
                &state,
                BrokerAuditFilter::all(),
                timestamp(301),
                crate::MAX_HUMAN_CONTROL_AUDIT_EVENTS,
                1,
            ),
            Err(BrokerAuditError::ExportTooLarge)
        ));
    }
}
