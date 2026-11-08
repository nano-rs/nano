-- NAN-4948: installed state of nano's signed platform feed bundle.
--
-- The ClickHouse product now loads IPinfo Lite, ThreatFox and the Tor exit
-- list from ONE signed bundle (nanosiem-core platform_enrichment::consumer).
-- The feed rows live in ClickHouse; this singleton records the LAST GOOD
-- install:
--   * signed_descriptor: the verified signed descriptor. It is the rollback
--     reference the next install is accepted against (sequence, per-feed
--     revision), and the status endpoint reads feed revisions, expiries and
--     the attribution NOTICE from it.
--   * feeds: what the install loaded per feed ({loaded, active, detail}).
--   * source / channel: online (open, sovereign, mirror) or offline (file).
--   * last_check_*, last_error*: the latest check. A refused or failed check
--     only touches these columns; the installed bundle stays.
--   * activation_pending: committed in ClickHouse, but some node has not yet
--     rebuilt its dictionaries from it (retried by the jobs leader).
--
-- ClickHouse is authoritative: every platform_feed_commits row carries the
-- full install receipt (signed descriptor included), and the consumer repairs
-- this row from the latest commit before any accept, expiry or reclaim, so a
-- crash between the ClickHouse commit and this write cannot split the two.
--
-- Forward-only and idempotent.

CREATE TABLE IF NOT EXISTS platform_feed_state (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    signed_descriptor JSONB,
    sequence BIGINT,
    payload_sha256 TEXT,
    container_sha256 TEXT,
    source TEXT CHECK (source IS NULL OR source IN ('online', 'offline')),
    channel TEXT CHECK (channel IS NULL OR channel IN ('open', 'sovereign', 'mirror', 'file')),
    installed_at TIMESTAMPTZ,
    feeds JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_check_at TIMESTAMPTZ,
    last_check_status TEXT,
    last_error TEXT,
    last_error_at TIMESTAMPTZ,
    activation_pending BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE platform_feed_state IS
    'NAN-4948: last good install of the signed platform feed bundle (feed rows live in ClickHouse) and the latest check.';
