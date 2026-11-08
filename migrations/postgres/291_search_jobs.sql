-- NAN-4915: durable search background jobs (ClickHouse edition).
--
-- Before this, async search jobs lived in an in-memory / Redis store with a
-- five-minute TTL and their results lived in process memory. A long search
-- died at the interactive budget, a search-service restart lost every running
-- job, and an analyst could not come back to a result without re-scanning.
--
-- One row per background search job. PostgreSQL holds only metadata and job
-- control; the result ROWS live in the ClickHouse `search_job_results` table
-- (24 h TTL, clickhouse/181), keyed by (job_id, attempt, seq).
--
-- LEASES AND FENCING
-- ------------------
-- A nanosiem-search worker claims a job with `FOR UPDATE SKIP LOCKED`, moving it
-- to `running`, bumping `attempt`, and stamping `lease_owner` +
-- `lease_expires_at`. It renews the lease while the ClickHouse query runs.
-- Every renewal and the final complete/fail write is fenced on
-- (id, lease_owner, attempt, state = 'running'): a worker whose lease expired
-- (process restart, network partition) and was reclaimed can never overwrite
-- the newer attempt or a cancellation. An expired lease is reclaimed by any
-- worker until `max_attempts` is reached, after which the job fails with
-- `error_kind = 'worker_lost'`.
--
-- ATTACH / REUSE
-- --------------
-- `identity_hash` is a digest of the normalized request (query, absolute time
-- range, dataset and view flags), the owner, and the owner's effective source
-- scope at submission. The partial unique index below allows exactly one
-- queued/running job per (owner, identity), so an identical submission attaches
-- to the running job instead of starting a second scan. It is per-owner on
-- purpose: attaching across principals would disclose that another user is
-- running the same search.
--
-- `scope_deny` / `scope_artifact_deny` stamp the source-scope deny-sets the job
-- executes under (NAN-2096 semantics). Every read re-checks the caller's CURRENT
-- deny-set against the stamp, so narrowing a user's scope makes their earlier
-- results unreadable.
CREATE TABLE IF NOT EXISTS public.search_jobs (
    -- TypeId prefix "sjob" at the serde layer.
    id UUID PRIMARY KEY,
    -- The authenticated subject that submitted the job (the api-key id for
    -- api-key auth, the user id for an interactive session).
    owner_user_id UUID NOT NULL,
    identity_hash TEXT NOT NULL,
    query TEXT NOT NULL,
    -- The normalized SearchRequest the worker executes (absolute time range).
    request JSONB NOT NULL,
    -- The page size the submitting client asked for. The job itself stores the
    -- whole capped result; this only sizes the inline first page of the status
    -- response so pre-existing pollers get the page they requested.
    page_limit INTEGER,
    time_start TIMESTAMPTZ NOT NULL,
    time_end TIMESTAMPTZ NOT NULL,
    scope_deny JSONB NOT NULL DEFAULT '[]'::jsonb,
    scope_artifact_deny JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- 'submitted': explicit background job (async_mode / POST /api/search/jobs).
    -- 'escalated': an interactive search that outran its budget and was handed
    -- off to a job.
    origin TEXT NOT NULL DEFAULT 'submitted',
    state TEXT NOT NULL DEFAULT 'queued',
    attempt INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    -- ClickHouse query_id of the CURRENT attempt (`<uuid>-a<attempt>`); the
    -- cancel path issues KILL QUERY against it from any replica.
    ch_query_id TEXT,
    progress JSONB,
    -- Set on completion: which attempt's rows in search_job_results are the
    -- result (rows from an abandoned attempt are ignored, then TTL'd).
    result_attempt INTEGER,
    row_count BIGINT,
    result_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    -- SearchResponse minus `results`: total_count, fields, histogram,
    -- display_type, column_order, warnings, execution_time_ms.
    result_meta JSONB,
    error_kind TEXT,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    heartbeat_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    CONSTRAINT search_jobs_state_check
        CHECK (state IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    CONSTRAINT search_jobs_origin_check
        CHECK (origin IN ('submitted', 'escalated')),
    CONSTRAINT search_jobs_error_kind_check
        CHECK (error_kind IS NULL OR error_kind IN (
            'cancelled', 'timeout', 'query_too_large', 'invalid_query',
            'worker_lost', 'internal'
        )),
    CONSTRAINT search_jobs_time_order CHECK (time_start < time_end),
    CONSTRAINT search_jobs_attempts_positive CHECK (max_attempts > 0)
);

-- Attach: at most one live job per (owner, identity).
CREATE UNIQUE INDEX IF NOT EXISTS idx_search_jobs_active_identity
    ON public.search_jobs (owner_user_id, identity_hash)
    WHERE state IN ('queued', 'running');

-- Claim scan: oldest queued first.
CREATE INDEX IF NOT EXISTS idx_search_jobs_queued
    ON public.search_jobs (created_at)
    WHERE state = 'queued';

-- Reclaim scan: running jobs whose lease has lapsed.
CREATE INDEX IF NOT EXISTS idx_search_jobs_running_lease
    ON public.search_jobs (lease_expires_at)
    WHERE state = 'running';

-- Owner job list (Active Searches / Running jobs panel).
CREATE INDEX IF NOT EXISTS idx_search_jobs_owner_created
    ON public.search_jobs (owner_user_id, created_at DESC);

-- Expiry sweep.
CREATE INDEX IF NOT EXISTS idx_search_jobs_expires
    ON public.search_jobs (expires_at);
