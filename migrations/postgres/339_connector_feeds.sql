-- NAN-3490 / NAN-3492: connector-engine feed tables, open tier.
--
-- The `nano-connector-runner` service (feeds, per-stream checkpoints, run
-- records) runs on open core too, so the tables are created here, in the
-- canonical history every edition applies. Open core / dedicated use them
-- single-tenant: rows carry the deployment's tenant (the compatibility tenant
-- from 319) and the runner uses the plain pool (`Tenancy::Dedicated`).
--
-- The enterprise overlay `9012400_connector_feeds.sql` carries the identical
-- CREATE TABLE IF NOT EXISTS (a no-op after this file) and adds what only a
-- multi-tenant lean deployment needs: FORCE RLS + registry/tenant policy,
-- data-owner ownership, the purge catalog and the 64-feed per-tenant cap.
-- Keep the two definitions identical; `nano-connector/tests/migration_parity.rs`
-- checks it.
--
-- See 9012400 for the column semantics (pinned spec + sha256, sealed
-- credentials, lease generation fencing, checkpoint-after-receipt).

CREATE TABLE IF NOT EXISTS public.connector_feeds (
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    name TEXT NOT NULL CHECK (
        length(name) BETWEEN 1 AND 100 AND name = btrim(name) AND name !~ '[[:cntrl:]]'
    ),
    -- Catalog slug of the connector, and the catalog entry it came from
    -- (informational: the pinned spec below is what runs).
    connector TEXT NOT NULL CHECK (connector ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    catalog_id UUID,
    spec_yaml TEXT NOT NULL CHECK (octet_length(spec_yaml) BETWEEN 1 AND 262144),
    spec_sha256 TEXT NOT NULL CHECK (spec_sha256 ~ '^[0-9a-f]{64}$'),
    -- The lane the feed's ingest credential is bound to.
    source_slug TEXT NOT NULL CHECK (
        source_slug ~ '^[a-z0-9][a-z0-9_-]{0,99}$' AND source_slug <> 'unknown'
    ),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    -- Cron override; NULL = the spec's `schedule`.
    schedule TEXT CHECK (length(schedule) BETWEEN 9 AND 120 AND schedule !~ '[[:cntrl:]]'),
    config JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (
        jsonb_typeof(config) = 'object' AND octet_length(config::text) <= 65536
    ),
    vendor_credentials_encrypted BYTEA CHECK (octet_length(vendor_credentials_encrypted) <= 65536),
    vendor_credentials_nonce TEXT CHECK (length(vendor_credentials_nonce) <= 64),
    ingest_url TEXT NOT NULL CHECK (
        ingest_url ~ '^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/|/services/collector/event)?$'
        AND length(ingest_url) <= 512
    ),
    ingest_credential_id UUID,
    ingest_token_encrypted BYTEA NOT NULL CHECK (octet_length(ingest_token_encrypted) <= 4096),
    ingest_token_nonce TEXT NOT NULL CHECK (length(ingest_token_nonce) <= 64),
    backfill_from TIMESTAMPTZ,
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
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_by UUID,
    updated_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT connector_feeds_tenant_name UNIQUE (tenant_id, name),
    CONSTRAINT connector_feeds_vendor_credentials_pair CHECK (
        (vendor_credentials_encrypted IS NULL) = (vendor_credentials_nonce IS NULL)
    ),
    CONSTRAINT connector_feeds_lease_pair CHECK (
        (lease_owner IS NULL) = (lease_expires_at IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS connector_feeds_due
    ON public.connector_feeds (tenant_id, next_run_at) WHERE enabled;

CREATE TABLE IF NOT EXISTS public.connector_feed_checkpoints (
    tenant_id UUID NOT NULL,
    feed_id UUID NOT NULL,
    stream_id TEXT NOT NULL CHECK (stream_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    state JSONB NOT NULL CHECK (octet_length(state::text) <= 16777216),
    lease_generation BIGINT NOT NULL CHECK (lease_generation >= 1),
    run_id UUID,
    commits BIGINT NOT NULL DEFAULT 1 CHECK (commits >= 1),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, feed_id, stream_id),
    CONSTRAINT connector_feed_checkpoints_feed_fkey FOREIGN KEY (tenant_id, feed_id)
        REFERENCES public.connector_feeds (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS public.connector_feed_runs (
    tenant_id UUID NOT NULL,
    id UUID NOT NULL,
    feed_id UUID NOT NULL,
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
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT connector_feed_runs_feed_fkey FOREIGN KEY (tenant_id, feed_id)
        REFERENCES public.connector_feeds (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT connector_feed_runs_finished CHECK (
        (status = 'running') = (finished_at IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS connector_feed_runs_feed_started
    ON public.connector_feed_runs (tenant_id, feed_id, started_at DESC);
