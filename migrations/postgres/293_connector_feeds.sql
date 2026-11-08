-- NAN-4914 phase 4: connector pull feeds (single-tenant).
--
-- The `nano-connector-runner` service runs bundled connector specs (Okta
-- System Log, Google Workspace, Slack, Netskope) as scheduled pull feeds and
-- delivers their events to the local Vector HEC listener. These tables hold
-- the feeds, their per-stream checkpoints and their run records.
--
-- Rewritten for the single-tenant ClickHouse product from main's 339 (+ 340,
-- 350, 352): no tenant column or `tenants` FK, no hosted ingest-token
-- issuance or sealed per-feed token (the runner holds the install's ingest
-- token), no identity sink, no pending-delete queue (a feed has no external
-- state, so removal is a plain DELETE). The feed's vendor secret is a
-- credential in the credentials store (`cloud_credentials`, providers added
-- by 298), so it gets versions, rotation and the credentials:use gate, and
-- can never be deleted while a feed is bound to it.
--
-- Invariants the runner relies on:
-- * a stream's checkpoint is written only while the writer holds the feed's
--   current `lease_generation` (fencing); pause, resume and checkpoint reset
--   bump the generation, so a run started before them cannot move a cursor;
-- * the cursor commits only after Vector acknowledged the events (HEC acks).
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS public.connector_feeds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL CHECK (
        length(name) BETWEEN 1 AND 100 AND name = btrim(name) AND name !~ '[[:cntrl:]]'
    ),
    -- Bundled spec slug; the pinned spec below is what runs.
    connector TEXT NOT NULL CHECK (connector ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    spec_yaml TEXT NOT NULL CHECK (octet_length(spec_yaml) BETWEEN 1 AND 262144),
    spec_sha256 TEXT NOT NULL CHECK (spec_sha256 ~ '^[0-9a-f]{64}$'),
    -- Parser lane label: the spec's stream source_type (a template such as
    -- `gws_{{item}}` for a fan-out spec). Display and audit only.
    source_type TEXT NOT NULL CHECK (length(source_type) BETWEEN 1 AND 128 AND source_type !~ '[[:cntrl:]]'),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    -- Cron override; NULL = the spec's `schedule`.
    schedule TEXT CHECK (length(schedule) BETWEEN 9 AND 120 AND schedule !~ '[[:cntrl:]]'),
    config JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (
        jsonb_typeof(config) = 'object' AND octet_length(config::text) <= 65536
    ),
    credential_id UUID REFERENCES public.cloud_credentials(id) ON DELETE RESTRICT,
    max_run_secs INTEGER CHECK (max_run_secs BETWEEN 10 AND 3600),
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_owner TEXT CHECK (length(lease_owner) <= 253),
    lease_expires_at TIMESTAMPTZ,
    lease_generation BIGINT NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    last_run_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_status TEXT CHECK (last_status IN ('success', 'failed', 'timeout', 'lease_lost')),
    last_error TEXT CHECK (length(last_error) <= 1100),
    created_by UUID,
    updated_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT connector_feeds_name_unique UNIQUE (name),
    CONSTRAINT connector_feeds_lease_pair CHECK (
        (lease_owner IS NULL) = (lease_expires_at IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS connector_feeds_due
    ON public.connector_feeds (next_run_at) WHERE enabled;
CREATE INDEX IF NOT EXISTS connector_feeds_credential
    ON public.connector_feeds (credential_id) WHERE credential_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.connector_feed_checkpoints (
    feed_id UUID NOT NULL REFERENCES public.connector_feeds(id) ON DELETE CASCADE,
    stream_id TEXT NOT NULL CHECK (stream_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    state JSONB NOT NULL CHECK (octet_length(state::text) <= 16777216),
    lease_generation BIGINT NOT NULL CHECK (lease_generation >= 1),
    run_id UUID,
    commits BIGINT NOT NULL DEFAULT 1 CHECK (commits >= 1),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (feed_id, stream_id)
);

CREATE TABLE IF NOT EXISTS public.connector_feed_runs (
    id UUID PRIMARY KEY,
    feed_id UUID NOT NULL REFERENCES public.connector_feeds(id) ON DELETE CASCADE,
    lease_generation BIGINT NOT NULL CHECK (lease_generation >= 1),
    node TEXT NOT NULL CHECK (length(node) BETWEEN 1 AND 253),
    status TEXT NOT NULL CHECK (status IN ('running', 'success', 'failed', 'timeout', 'lease_lost')),
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    spec_sha256 TEXT NOT NULL CHECK (spec_sha256 ~ '^[0-9a-f]{64}$'),
    events BIGINT NOT NULL DEFAULT 0 CHECK (events >= 0),
    bytes BIGINT NOT NULL DEFAULT 0 CHECK (bytes >= 0),
    batches BIGINT NOT NULL DEFAULT 0 CHECK (batches >= 0),
    pages INTEGER NOT NULL DEFAULT 0 CHECK (pages >= 0),
    requests INTEGER NOT NULL DEFAULT 0 CHECK (requests >= 0),
    ingest_retries BIGINT NOT NULL DEFAULT 0 CHECK (ingest_retries >= 0),
    rejected_events BIGINT NOT NULL DEFAULT 0 CHECK (rejected_events >= 0),
    dropped_duplicates BIGINT NOT NULL DEFAULT 0 CHECK (dropped_duplicates >= 0),
    checkpoints_committed BIGINT NOT NULL DEFAULT 0 CHECK (checkpoints_committed >= 0),
    errors INTEGER NOT NULL DEFAULT 0 CHECK (errors >= 0),
    error TEXT CHECK (length(error) <= 1100),
    last_receipt TEXT CHECK (length(last_receipt) <= 200),
    CONSTRAINT connector_feed_runs_finished CHECK (
        (status = 'running') = (finished_at IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS connector_feed_runs_feed_started
    ON public.connector_feed_runs (feed_id, started_at DESC);

COMMENT ON TABLE public.connector_feeds IS
    'NAN-4914: connector pull feeds run by nano-connector-runner (pinned bundled spec, credential binding, lease-fenced schedule)';
COMMENT ON TABLE public.connector_feed_checkpoints IS
    'NAN-4914: per-stream connector cursors, written only by the lease holder after Vector acknowledged the events';
COMMENT ON TABLE public.connector_feed_runs IS
    'NAN-4914: connector feed run records (30-day retention, pruned by the runner)';
