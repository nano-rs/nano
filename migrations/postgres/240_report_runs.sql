-- NAN-1793: scheduled report run history + artifacts.
--
-- report_runs: one row per execution of a report definition (scheduled or
-- manual). The row is created 'running' at execution start keyed by the durable
-- claim_run_id, so a stale-claim reclaim on another replica UPDATEs the same row
-- rather than spawning a duplicate (INSERT ... ON CONFLICT (id) DO UPDATE).
-- Terminal status is 'success' or 'failed'; a failed run records the error. No
-- panics in the scheduler — every failure lands here as 'failed' (NAN-1102).
--
-- Truncation is never silent: `truncated` flags the RESULT row cap being hit
-- (more rows matched than were rendered) and `artifact_truncated` flags the
-- per-artifact byte cap being hit. Both are surfaced in the run list and stamped
-- into the rendered report itself.
--
-- report_run_artifacts: one row per produced artifact (a search run yields a CSV
-- + an HTML summary; a dashboard run yields a single HTML report). Bytes live in
-- this dedicated table (not on report_runs) so run-history listing never pulls
-- bytea — the download endpoint is the only reader of `content`.
--
-- Storage choice (justified in the PR): the codebase has no general blob/object
-- store, so artifacts use PG bytea with a HARD per-artifact byte cap enforced in
-- the renderer (content beyond the cap is truncated + flagged). Retention prunes
-- to the definition's last-N runs, and ON DELETE CASCADE reaps artifacts with
-- their run, so total bytes stay bounded (cap × retention × definitions) with no
-- new storage dependency.

CREATE TABLE IF NOT EXISTS report_runs (
    id            UUID PRIMARY KEY,
    definition_id UUID NOT NULL REFERENCES report_definitions(id) ON DELETE CASCADE,

    -- 'running' | 'success' | 'failed'
    status        TEXT NOT NULL,
    -- 'schedule' | 'manual'
    triggered_by  TEXT NOT NULL DEFAULT 'schedule',

    started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at   TIMESTAMPTZ,
    duration_ms   BIGINT,

    -- Total result rows rendered (search reports; NULL for dashboard reports).
    row_count     BIGINT,
    -- Result row cap hit and more rows matched (visible truncation).
    truncated          BOOLEAN NOT NULL DEFAULT FALSE,
    -- An artifact hit the per-artifact byte cap and was truncated.
    artifact_truncated BOOLEAN NOT NULL DEFAULT FALSE,

    error         TEXT,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Run-history listing + retention pruning: newest-first per definition.
CREATE INDEX IF NOT EXISTS idx_report_runs_definition
    ON report_runs (definition_id, started_at DESC);

CREATE TABLE IF NOT EXISTS report_run_artifacts (
    id            UUID PRIMARY KEY,
    run_id        UUID NOT NULL REFERENCES report_runs(id) ON DELETE CASCADE,

    -- 'csv' | 'html'
    kind          TEXT NOT NULL,
    filename      TEXT NOT NULL,
    content_type  TEXT NOT NULL,
    size_bytes    BIGINT NOT NULL,
    content       BYTEA NOT NULL,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fetch a run's artifacts (list + download).
CREATE INDEX IF NOT EXISTS idx_report_run_artifacts_run
    ON report_run_artifacts (run_id);
