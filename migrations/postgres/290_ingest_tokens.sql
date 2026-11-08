-- NAN-4907: named, revocable per-source ingest tokens on the ClickHouse product.
--
-- Ported from main's open-core model (NAN-3770 `358_ingest_tokens.sql` +
-- NAN-3806 `363_ingest_token_sources.sql`), merged into one file and made
-- single-tenant: this product has no `tenants` table, so neither table carries
-- a tenant column, and the settings table is a singleton row.
--
-- An admin issues one token per sender, bound to one log source. The value is
-- shown once and never stored: only its SHA-256 (lowercase hex) and a short
-- display prefix are kept. nano-api renders the active hashes into Vector's
-- hashed tokens file (`/etc/vector/dynamic/ingest-tokens/tokens.json`), which
-- the HTTP and HEC ingest sources re-read every 2 s (nano-rs/vector
-- `valid_tokens_file`), so a revoke takes effect without a Vector reload. The
-- file entry's `name` is the bound source's route key: Vector stamps it as
-- `%nano_credential_name` and the lanes set `.source_type` from it, so the
-- token, not what the sender declares, decides the source.
--
-- The install-wide VECTOR_AUTH_TOKEN ("install token") has three states:
--   * legacy_multiplex: accepted and routed by the sender's X-Source-Type /
--     sourcetype, exactly as before this migration. Deprecated; kept so an
--     upgrade never breaks a sender that multiplexes many sources over it.
--   * strict, bound: accepted, every event lands in the bound source.
--   * strict, unbound (or disabled): refused with HTTP 401.
-- Existing installs (any non-system user exists) start in legacy_multiplex.
-- A fresh install starts strict and unbound: senders use named tokens.
--
-- Deleting a log source unbinds its tokens (ON DELETE SET NULL): they drop out
-- of the file, Vector refuses them, and an admin can bind them again.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS ingest_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL CHECK (
        length(name) BETWEEN 1 AND 100 AND name = btrim(name) AND name !~ '[[:cntrl:]]'
    ),
    -- The public `nit_` marker plus the first 8 random characters, to
    -- recognise a token in a sender's config. Never enough to use it.
    token_prefix TEXT NOT NULL CHECK (token_prefix ~ '^nit_[A-Za-z0-9]{8}$'),
    token_sha256 TEXT NOT NULL CHECK (token_sha256 ~ '^[0-9a-f]{64}$'),
    source_id UUID REFERENCES log_sources(id) ON DELETE SET NULL,
    source_bound_at TIMESTAMPTZ,
    source_bound_by UUID,
    -- Set on a token issued by rotating another one.
    rotated_from UUID REFERENCES ingest_tokens(id) ON DELETE SET NULL,
    -- Two-phase rotation: the replacement is inserted pending (listed in
    -- Vector's file next to the old token, never in the API listing), and
    -- only once the file with it is published is the old token revoked and
    -- the flag cleared. A failed publish deletes the pending row, so the old
    -- token keeps working. A pending row whose plaintext was never returned
    -- (crash mid-rotation) is purged by the reconcile.
    rotation_pending BOOLEAN NOT NULL DEFAULT FALSE,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Approximate: sampled from Vector's per-credential request counter
    -- (`hashed_token_requests_total{credential_id}`). `vector_request_counter`
    -- is the last raw counter value seen, so a counter reset after a Vector
    -- restart is detected and several API replicas never double count.
    last_used_at TIMESTAMPTZ,
    request_count BIGINT NOT NULL DEFAULT 0,
    vector_request_counter DOUBLE PRECISION,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID,
    CHECK (revoked_by IS NULL OR revoked_at IS NOT NULL)
);

-- A hash identifies at most one token (Vector's file is keyed by it).
CREATE UNIQUE INDEX IF NOT EXISTS ingest_tokens_sha256 ON ingest_tokens (token_sha256);
-- Names identify senders: unique among active tokens, case-insensitively. A
-- pending rotation replacement shares its predecessor's name until it commits.
CREATE UNIQUE INDEX IF NOT EXISTS ingest_tokens_active_name
    ON ingest_tokens (lower(name)) WHERE revoked_at IS NULL AND NOT rotation_pending;
-- At most one pending rotation per token.
CREATE UNIQUE INDEX IF NOT EXISTS ingest_tokens_one_pending_rotation
    ON ingest_tokens (rotated_from) WHERE rotation_pending;
CREATE INDEX IF NOT EXISTS ingest_tokens_source ON ingest_tokens (source_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS ingest_token_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    install_token_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    install_token_mode TEXT NOT NULL DEFAULT 'strict'
        CHECK (install_token_mode IN ('strict', 'legacy_multiplex')),
    install_token_source_id UUID REFERENCES log_sources(id) ON DELETE SET NULL,
    install_token_source_bound_at TIMESTAMPTZ,
    install_token_source_bound_by UUID,
    updated_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Upgrade vs fresh install. Strict only when NOTHING suggests a pre-existing
-- deployment whose senders may multiplex over the install token; any one of
-- these signals selects legacy multiplex:
--   * a real (non-system) user (migrations run before the first admin);
--   * an earlier migration applied more than an hour ago (a fresh install
--     applies the whole chain in one boot);
--   * a log source or source configuration created more than an hour ago;
--   * any log source deployment record (only the running product deploys).
-- Idempotent: an existing row is never touched.
DO $nan4907_install_mode$
DECLARE
    v_existing BOOLEAN := FALSE;
BEGIN
    IF to_regclass('users') IS NOT NULL THEN
        EXECUTE 'SELECT EXISTS (SELECT 1 FROM users WHERE status IS DISTINCT FROM ''system'')'
           INTO v_existing;
    END IF;
    IF NOT v_existing AND to_regclass('_sqlx_migrations') IS NOT NULL THEN
        EXECUTE 'SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE installed_on < now() - interval ''1 hour'')'
           INTO v_existing;
    END IF;
    IF NOT v_existing AND to_regclass('log_sources') IS NOT NULL THEN
        EXECUTE 'SELECT EXISTS (SELECT 1 FROM log_sources WHERE created_at < now() - interval ''1 hour'')'
           INTO v_existing;
    END IF;
    IF NOT v_existing AND to_regclass('source_configurations') IS NOT NULL THEN
        EXECUTE 'SELECT EXISTS (SELECT 1 FROM source_configurations WHERE created_at < now() - interval ''1 hour'')'
           INTO v_existing;
    END IF;
    IF NOT v_existing AND to_regclass('log_source_deployments') IS NOT NULL THEN
        EXECUTE 'SELECT EXISTS (SELECT 1 FROM log_source_deployments)'
           INTO v_existing;
    END IF;
    INSERT INTO ingest_token_settings (singleton, install_token_mode)
    VALUES (TRUE, CASE WHEN v_existing THEN 'legacy_multiplex' ELSE 'strict' END)
    ON CONFLICT (singleton) DO NOTHING;
END
$nan4907_install_mode$;
