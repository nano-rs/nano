-- NAN-1793: scheduled report definitions.
--
-- A report definition schedules (cron) either a saved SEARCH (an nPL query run
-- over a relative time window) or a DASHBOARD (its panel queries executed
-- server-side) to produce a downloadable artifact on a recurrence. Completed
-- runs notify the owner in-app and emit a `report_ready` outbound webhook.
--
-- Execution identity (NAN-1793): runs execute AS THE OWNER captured here at
-- definition time. The internal search-execution path has no per-source row-RBAC
-- yet (a parallel RBAC design effort owns that), so v1 executes as system while
-- storing owner_id — the future-proof seam once search gains a permission
-- context. See nanosiem-core/src/reports/service.rs (execute_definition).
--
-- Distributed execution reuses the scheduled_jobs SKIP LOCKED claiming pattern
-- (migration 228 fencing) verbatim: claimed_by / claimed_at / claim_generation /
-- claim_run_id so exactly one replica runs a due definition and a crashed node's
-- claim is reclaimed after a stale timeout without double-execution.

CREATE TABLE IF NOT EXISTS report_definitions (
    id                UUID PRIMARY KEY,
    name              TEXT NOT NULL,
    description       TEXT,

    -- 'search' | 'dashboard' (validated in the application layer, mirroring the
    -- webhook event_types convention so adding a future source needs no CHECK
    -- migration).
    source_type       TEXT NOT NULL,

    -- SEARCH source: the nPL query snapshot to run. NULL for dashboard reports.
    source_query      TEXT,
    -- Optional provenance link back to the query_library entry the search was
    -- saved from (query_library uses integer ids). Informational only.
    saved_query_id    INTEGER,

    -- DASHBOARD source: the dashboard whose panels are executed. NULL for search
    -- reports. CASCADE so deleting a dashboard removes its report definitions.
    source_dashboard_id UUID REFERENCES dashboards(id) ON DELETE CASCADE,

    -- Relative lookback window in seconds applied at run time as
    -- [now() - time_range_seconds, now()]. Relative (not absolute) so a recurring
    -- report always covers the trailing window rather than a frozen range.
    time_range_seconds BIGINT NOT NULL DEFAULT 86400,

    cron_expression   TEXT NOT NULL,

    -- Owner captured at definition time; runs execute under this identity.
    -- CASCADE so a deleted user's report definitions are removed with them.
    owner_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    enabled           BOOLEAN NOT NULL DEFAULT TRUE,

    -- Retention: keep at most this many most-recent runs per definition; the
    -- scheduler prunes older runs (and their artifacts) after each successful
    -- run. Bounds unbounded artifact growth (artifacts are PG bytea).
    retention_runs    INTEGER NOT NULL DEFAULT 20,

    last_run_at       TIMESTAMPTZ,
    last_run_status   TEXT,
    last_run_error    TEXT,
    next_run_at       TIMESTAMPTZ,

    -- Distributed-claim state (SKIP LOCKED). Mirrors scheduled_jobs.
    claimed_by        TEXT,
    claimed_at        TIMESTAMPTZ,
    claim_generation  BIGINT NOT NULL DEFAULT 0,
    claim_run_id      UUID,

    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Due-work claim scan: enabled + due, ordered by next_run_at.
CREATE INDEX IF NOT EXISTS idx_report_definitions_due
    ON report_definitions (next_run_at)
    WHERE enabled = TRUE;

-- Owner-scoped listing.
CREATE INDEX IF NOT EXISTS idx_report_definitions_owner
    ON report_definitions (owner_id);

-- Dashboard-source lookups (and CASCADE integrity).
CREATE INDEX IF NOT EXISTS idx_report_definitions_dashboard
    ON report_definitions (source_dashboard_id);
