-- NAN-1768: serialize detection-rule version allocation and enforce a single
-- active history row. This invariant belongs to the common schema because
-- detection_rules and detection_rule_versions exist in every edition.

LOCK TABLE detection_rules, detection_rule_versions IN ACCESS EXCLUSIVE MODE;

-- Snapshot the live rule whenever history is ambiguous (zero/multiple active
-- rows) or the sole active row does not match the rule nano is actually using.
-- Re-activating an arbitrary historical row would make rollback/audit views lie
-- about production state.
WITH affected_rules AS MATERIALIZED (
    SELECT rule.id
    FROM detection_rules AS rule
    LEFT JOIN detection_rule_versions AS version ON version.rule_id = rule.id
    GROUP BY
        rule.id,
        rule.query,
        rule.name,
        rule.description,
        rule.severity,
        rule.mode
    HAVING COUNT(*) FILTER (WHERE version.is_active = true) <> 1
        OR COUNT(*) FILTER (
            WHERE version.is_active = true
              AND version.query = rule.query
              AND version.name = rule.name
              AND version.description IS NOT DISTINCT FROM rule.description
              AND version.severity = rule.severity
              AND version.enabled = (rule.mode NOT IN ('staging', 'paused'))
        ) <> 1
), deactivated AS (
    UPDATE detection_rule_versions AS version
    SET is_active = false
    FROM affected_rules
    WHERE version.rule_id = affected_rules.id
      AND version.is_active = true
    RETURNING version.id
)
INSERT INTO detection_rule_versions (
    rule_id, version_number, query, name, description, severity,
    enabled, is_active, created_by, change_reason,
    tuning_proposal_id, reverted_from_version
)
SELECT
    rule.id,
    COALESCE(MAX(version.version_number), 0) + 1,
    rule.query,
    rule.name,
    rule.description,
    rule.severity,
    rule.mode NOT IN ('staging', 'paused'),
    true,
    NULL,
    'atomic_state_repair',
    NULL,
    NULL
FROM affected_rules
JOIN detection_rules AS rule ON rule.id = affected_rules.id
LEFT JOIN detection_rule_versions AS version ON version.rule_id = rule.id
GROUP BY
    rule.id,
    rule.query,
    rule.name,
    rule.description,
    rule.severity,
    rule.mode;

CREATE UNIQUE INDEX IF NOT EXISTS uq_detection_rule_versions_active
    ON detection_rule_versions (rule_id)
    WHERE is_active = true;

COMMENT ON INDEX uq_detection_rule_versions_active IS
    'At most one active detection-rule version per rule';

-- PostgreSQL is the source of truth for tuning state, but real-time rules also
-- execute through a ClickHouse materialized view. Persist reconciliation in the
-- same transaction as a query/version mutation so crashes and transient DDL
-- failures cannot leave the execution plane silently stale. NAN-1772's rollback
-- migration deliberately uses the same idempotent table contract.
CREATE TABLE IF NOT EXISTS detection_rule_runtime_sync_jobs (
    -- No foreign key: a deleted rule leaves a tombstone until its orphaned view
    -- has been removed from ClickHouse.
    rule_id UUID PRIMARY KEY,
    desired_version_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    claimed_by TEXT,
    claimed_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_detection_rule_runtime_sync_claim
    ON detection_rule_runtime_sync_jobs (status, claimed_at, updated_at);
