-- NAN-3770: named, revocable per-sender ingest tokens (open core / dedicated).
--
-- An admin issues a token per sender. Its value is shown once and never
-- stored: only its SHA-256 (lowercase hex) and a short display prefix are
-- kept. nano-api renders the active hashes into Vector's hashed tokens file
-- (`/etc/vector/dynamic/ingest-tokens/tokens.json`), which the HEC and HTTP
-- ingest sources re-read within seconds, so a revoke takes effect without a
-- Vector reload. Events from a named token carry `metadata.nano_credential_id`
-- (this table's `id`).
--
-- Single-tenant on open core, tenant-scoped anyway: rows carry the
-- deployment's tenant (the compatibility tenant from 319), like
-- connector_feeds (339). Hosted tenants issue credentials through the edge
-- Worker flow instead (`/api/log-sources/ingest-credentials`); this table is
-- unused there.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS public.ingest_tokens (
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    name TEXT NOT NULL CHECK (
        length(name) BETWEEN 1 AND 100 AND name = btrim(name) AND name !~ '[[:cntrl:]]'
    ),
    -- First characters of the token (the public `nit_` marker plus 8), for
    -- recognising a token in a sender's config. Never enough to use it.
    token_prefix TEXT NOT NULL CHECK (token_prefix ~ '^nit_[A-Za-z0-9]{8}$'),
    token_sha256 TEXT NOT NULL CHECK (token_sha256 ~ '^[0-9a-f]{64}$'),
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Approximate (the API samples Vector's per-credential request counter).
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID,
    PRIMARY KEY (tenant_id, id),
    CHECK (revoked_by IS NULL OR revoked_at IS NOT NULL)
);

-- A hash identifies at most one token anywhere (Vector's file is keyed by it).
CREATE UNIQUE INDEX IF NOT EXISTS ingest_tokens_sha256
    ON public.ingest_tokens (token_sha256);
-- Names identify senders: unique among a tenant's active tokens.
CREATE UNIQUE INDEX IF NOT EXISTS ingest_tokens_active_name
    ON public.ingest_tokens (tenant_id, lower(name)) WHERE revoked_at IS NULL;

-- Per-tenant settings. `install_token_enabled` = whether the install-wide
-- VECTOR_AUTH_TOKEN ("Install token (legacy)") is still accepted alongside the
-- named tokens. No row = enabled.
CREATE TABLE IF NOT EXISTS public.ingest_token_settings (
    tenant_id UUID PRIMARY KEY REFERENCES public.tenants(id) ON DELETE CASCADE,
    install_token_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
