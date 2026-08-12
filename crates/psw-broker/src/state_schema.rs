pub(crate) const CURRENT_DEVICE_SCHEMA_VERSION: i64 = 2;

pub(crate) const REQUIRED_TABLES_V1: &[&str] = &[
    "access_rules",
    "approvals",
    "audit_events",
    "consumers",
    "device_settings",
    "usage_profiles",
    "use_grants",
];

pub(crate) const REQUIRED_TABLES: &[&str] = &[
    "access_rules",
    "approvals",
    "audit_events",
    "consumers",
    "controller_authority",
    "device_settings",
    "usage_profiles",
    "use_grants",
];

pub(crate) const CREATE_SCHEMA_V1: &str = r#"
CREATE TABLE consumers (
    consumer_id TEXT PRIMARY KEY,
    pairing_public_key BLOB NOT NULL CHECK(length(pairing_public_key) = 32),
    label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 128),
    executable_name TEXT CHECK(executable_name IS NULL OR length(executable_name) BETWEEN 1 AND 128),
    bundle_identifier TEXT CHECK(bundle_identifier IS NULL OR length(bundle_identifier) BETWEEN 1 AND 255),
    team_identifier TEXT CHECK(team_identifier IS NULL OR length(team_identifier) BETWEEN 1 AND 64),
    code_signature_digest BLOB CHECK(code_signature_digest IS NULL OR length(code_signature_digest) = 32),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0)
) STRICT;

CREATE TABLE access_rules (
    access_rule_id TEXT PRIMARY KEY,
    consumer_id TEXT NOT NULL REFERENCES consumers(consumer_id) ON DELETE CASCADE,
    vault_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    secret_field_id TEXT NOT NULL,
    capability_name TEXT NOT NULL,
    capability_version INTEGER NOT NULL CHECK(capability_version BETWEEN 1 AND 65535),
    confirmation_policy TEXT NOT NULL CHECK(confirmation_policy IN (
        'every-use',
        'once-per-unlock-session',
        'automatic-while-unlocked'
    )),
    expires_at_ms INTEGER CHECK(expires_at_ms IS NULL OR expires_at_ms >= 0),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    CHECK(expires_at_ms IS NULL OR expires_at_ms > created_at_ms),
    UNIQUE(
        consumer_id,
        vault_id,
        credential_id,
        secret_field_id,
        capability_name,
        capability_version
    )
) STRICT;

CREATE TABLE use_grants (
    use_grant_id TEXT PRIMARY KEY,
    consumer_id TEXT NOT NULL REFERENCES consumers(consumer_id) ON DELETE CASCADE,
    vault_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    secret_field_id TEXT NOT NULL,
    capability_name TEXT NOT NULL,
    capability_version INTEGER NOT NULL CHECK(capability_version BETWEEN 1 AND 65535),
    source_rule_id TEXT REFERENCES access_rules(access_rule_id) ON DELETE CASCADE,
    vault_session_id TEXT NOT NULL,
    grant_scope TEXT NOT NULL CHECK(grant_scope IN ('one-operation', 'unlock-session')),
    remaining_uses INTEGER CHECK(
        (grant_scope = 'one-operation' AND remaining_uses = 1)
        OR (grant_scope = 'unlock-session' AND remaining_uses IS NULL)
    ),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > created_at_ms)
) STRICT;

CREATE TABLE usage_profiles (
    usage_profile_id TEXT PRIMARY KEY,
    consumer_id TEXT NOT NULL REFERENCES consumers(consumer_id) ON DELETE CASCADE,
    label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 128),
    capability_name TEXT NOT NULL,
    capability_version INTEGER NOT NULL CHECK(capability_version BETWEEN 1 AND 65535),
    definition_version INTEGER NOT NULL CHECK(definition_version = 1),
    placement_json TEXT NOT NULL CHECK(length(placement_json) BETWEEN 2 AND 2048),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0)
) STRICT;

CREATE TABLE approvals (
    approval_request_id TEXT PRIMARY KEY,
    approval_kind TEXT NOT NULL CHECK(approval_kind IN (
        'pairing',
        'unlock',
        'access',
        'credential-access'
    )),
    consumer_id TEXT NOT NULL,
    pairing_public_key BLOB CHECK(pairing_public_key IS NULL OR length(pairing_public_key) = 32),
    executable_name TEXT CHECK(executable_name IS NULL OR length(executable_name) BETWEEN 1 AND 128),
    bundle_identifier TEXT CHECK(bundle_identifier IS NULL OR length(bundle_identifier) BETWEEN 1 AND 255),
    team_identifier TEXT CHECK(team_identifier IS NULL OR length(team_identifier) BETWEEN 1 AND 64),
    code_signature_digest BLOB CHECK(code_signature_digest IS NULL OR length(code_signature_digest) = 32),
    vault_id TEXT,
    credential_id TEXT,
    secret_field_id TEXT,
    capability_name TEXT,
    capability_version INTEGER CHECK(capability_version IS NULL OR capability_version BETWEEN 1 AND 65535),
    coalescing_digest BLOB NOT NULL CHECK(length(coalescing_digest) = 32),
    approval_status TEXT NOT NULL CHECK(approval_status IN (
        'pending',
        'approved',
        'denied',
        'expired',
        'cancelled'
    )),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > created_at_ms),
    resolved_at_ms INTEGER CHECK(resolved_at_ms IS NULL OR resolved_at_ms >= created_at_ms),
    CHECK(
        (approval_status = 'pending' AND resolved_at_ms IS NULL)
        OR (approval_status <> 'pending' AND resolved_at_ms IS NOT NULL)
    ),
    CHECK(
        (
            approval_kind = 'pairing'
            AND pairing_public_key IS NOT NULL
            AND vault_id IS NULL
            AND credential_id IS NULL
            AND secret_field_id IS NULL
            AND capability_name IS NULL
            AND capability_version IS NULL
        )
        OR (
            approval_kind = 'unlock'
            AND pairing_public_key IS NULL
            AND executable_name IS NULL
            AND bundle_identifier IS NULL
            AND team_identifier IS NULL
            AND code_signature_digest IS NULL
            AND vault_id IS NOT NULL
            AND credential_id IS NULL
            AND secret_field_id IS NULL
            AND capability_name IS NULL
            AND capability_version IS NULL
        )
        OR (
            approval_kind = 'access'
            AND pairing_public_key IS NULL
            AND executable_name IS NULL
            AND bundle_identifier IS NULL
            AND team_identifier IS NULL
            AND code_signature_digest IS NULL
            AND vault_id IS NOT NULL
            AND credential_id IS NOT NULL
            AND secret_field_id IS NOT NULL
            AND capability_name IS NOT NULL
            AND capability_version IS NOT NULL
        )
        OR (
            approval_kind = 'credential-access'
            AND pairing_public_key IS NULL
            AND executable_name IS NULL
            AND bundle_identifier IS NULL
            AND team_identifier IS NULL
            AND code_signature_digest IS NULL
            AND vault_id IS NOT NULL
            AND credential_id IS NULL
            AND secret_field_id IS NULL
            AND capability_name IS NOT NULL
            AND capability_version IS NOT NULL
        )
    )
) STRICT;

CREATE TABLE audit_events (
    audit_event_id TEXT PRIMARY KEY,
    occurred_at_ms INTEGER NOT NULL CHECK(occurred_at_ms >= 0),
    event_kind TEXT NOT NULL CHECK(event_kind IN (
        'pairing',
        'authorization',
        'grant',
        'credential-use',
        'pause',
        'revocation'
    )),
    consumer_id TEXT,
    vault_id TEXT,
    credential_id TEXT,
    secret_field_id TEXT,
    capability_name TEXT,
    capability_version INTEGER CHECK(capability_version IS NULL OR capability_version BETWEEN 1 AND 65535),
    decision TEXT NOT NULL CHECK(decision IN (
        'allowed',
        'denied',
        'pending',
        'revoked',
        'paused',
        'resumed',
        'failed'
    )),
    confirmation_method TEXT NOT NULL CHECK(confirmation_method IN (
        'none',
        'user-approval',
        'master-password',
        'local-authentication',
        'persistent-rule'
    )),
    use_grant_id TEXT,
    CHECK(
        (vault_id IS NULL AND credential_id IS NULL AND secret_field_id IS NULL)
        OR (vault_id IS NOT NULL AND credential_id IS NOT NULL AND secret_field_id IS NOT NULL)
    ),
    CHECK(
        (capability_name IS NULL AND capability_version IS NULL)
        OR (capability_name IS NOT NULL AND capability_version IS NOT NULL)
    )
) STRICT;

CREATE TABLE device_settings (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    apps_tools_paused INTEGER NOT NULL CHECK(apps_tools_paused IN (0, 1)),
    audit_retention_days INTEGER NOT NULL CHECK(audit_retention_days BETWEEN 1 AND 3650),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms)
) STRICT;

CREATE INDEX access_rules_by_consumer
ON access_rules(consumer_id, vault_id, credential_id, secret_field_id);

CREATE INDEX use_grants_by_consumer_and_expiry
ON use_grants(consumer_id, expires_at_ms);

CREATE INDEX use_grants_by_vault_session
ON use_grants(vault_id, vault_session_id);

CREATE INDEX use_grants_by_field
ON use_grants(vault_id, credential_id, secret_field_id);

CREATE INDEX access_rules_by_field
ON access_rules(vault_id, credential_id, secret_field_id);

CREATE INDEX usage_profiles_by_consumer
ON usage_profiles(consumer_id, label);

CREATE UNIQUE INDEX one_pending_approval_per_digest
ON approvals(coalescing_digest)
WHERE approval_status = 'pending';

CREATE INDEX approvals_by_status_and_expiry
ON approvals(approval_status, expires_at_ms);

CREATE INDEX approvals_by_field
ON approvals(vault_id, credential_id, secret_field_id);

CREATE INDEX audit_events_by_time
ON audit_events(occurred_at_ms DESC, audit_event_id);

PRAGMA user_version = 1;
"#;

pub(crate) const MIGRATE_SCHEMA_V1_TO_V2: &str = r#"
CREATE TABLE controller_authority (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    contract_id TEXT NOT NULL CHECK(contract_id = 'keptnear.controller-authority.v1'),
    signing_algorithm TEXT NOT NULL CHECK(signing_algorithm = 'ed25519'),
    controller_id BLOB NOT NULL UNIQUE CHECK(length(controller_id) = 32),
    public_key BLOB NOT NULL UNIQUE CHECK(length(public_key) = 32),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0)
) STRICT;

PRAGMA user_version = 2;
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_contains_only_device_trust_and_non_secret_audit_columns() {
        for forbidden in [
            "master_password",
            "recovery_key",
            "vault_key",
            "secret_value",
            "credential_title",
            "request_body",
            "request_url",
            "response_body",
            "api_response_body",
            "command_argument",
            "standard_output",
            "standard_error",
            "stdout",
            "stderr",
            "executable_path",
            "vault_path",
            "url ",
        ] {
            assert!(
                !CREATE_SCHEMA_V1.contains(forbidden)
                    && !MIGRATE_SCHEMA_V1_TO_V2.contains(forbidden),
                "device schema contains forbidden column category {forbidden}"
            );
        }
    }

    #[test]
    fn every_required_table_is_declared_once() {
        for table in REQUIRED_TABLES_V1 {
            assert_eq!(
                CREATE_SCHEMA_V1
                    .matches(&format!("CREATE TABLE {table} "))
                    .count(),
                1,
                "unexpected declaration count for {table}"
            );
        }
        assert_eq!(
            MIGRATE_SCHEMA_V1_TO_V2
                .matches("CREATE TABLE controller_authority ")
                .count(),
            1
        );
    }
}
