-- NAN-4954: durable record of security-critical audit events.
--
-- Since NAN-1622 ClickHouse has been the only audit store. Security-critical
-- events (logins, MFA, password, API-key and ingest-token lifecycle, ... — see
-- nanosiem_core::audit::SECURITY_CRITICAL_ACTIONS) were written with a
-- synchronous ClickHouse insert; when that insert failed (MEMORY_LIMIT_EXCEEDED
-- code 241, timeout, outage) the event existed only as an application log line.
--
-- This table is the PostgreSQL record of truth for those events and the outbox
-- that delivers them to ClickHouse:
--   * every security-critical event is inserted here BEFORE the ClickHouse
--     write is attempted;
--   * a successful inline write stamps udm_delivered_at / ocsf_delivered_at /
--     delivered_at;
--   * a failed write leaves the row pending, and the jobs drainer retries it
--     with backoff (next_attempt_at) until ClickHouse accepts it;
--   * GET /api/audit serves these rows (flagged degraded) when ClickHouse cannot
--     answer, and SIEM Health reports the pending backlog.
--
-- Delivered rows are kept for the retention window (pruned by the drainer);
-- pending rows are never pruned.
--
-- Forward-only and idempotent.

CREATE TABLE IF NOT EXISTS security_audit_events (
    event_id UUID PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL,
    action TEXT NOT NULL,
    actor_id UUID,
    resource_type TEXT,
    success BOOLEAN NOT NULL,
    -- The full serialized nanosiem_core::audit::AuditEvent.
    event JSONB NOT NULL,
    udm_delivered_at TIMESTAMPTZ,
    ocsf_delivered_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    last_attempt_at TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Drainer claim path: pending rows in due order.
CREATE INDEX IF NOT EXISTS idx_security_audit_events_pending
    ON security_audit_events (next_attempt_at)
    WHERE delivered_at IS NULL;

-- Degraded /api/audit read path and retention prune.
CREATE INDEX IF NOT EXISTS idx_security_audit_events_occurred
    ON security_audit_events (occurred_at DESC);
