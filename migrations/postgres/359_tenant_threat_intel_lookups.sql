-- NAN-3763: agent-driven threat-intel lookups (VirusTotal, AbuseIPDB,
-- GreyNoise, URLhaus, ThreatFox, MalwareBazaar, Shodan) as investigation
-- tools for auto-investigation, pivt and the "Enrich" action.
--
-- Three tenant-keyed tables (tenant-first keys, tenant-paired FKs) so the
-- enterprise overlay (9013550) can register them for RLS on hosted-shared:
--
-- * tenant_ti_providers: which official lookup specs a tenant enabled, its
--   sealed credential (AES-256-GCM under the process cipher, the same
--   (BYTEA ciphertext, nonce) shape as cloud_credentials; the plaintext
--   binds tenant_id + provider and is checked on open) and optional limit /
--   cache-TTL overrides. No request definitions: specs ship with the build.
-- * tenant_ti_lookup_cache: the tenant's own normalized results (verdict,
--   score, link, tags, a bounded summary; never the raw provider body),
--   keyed by sha256 of the normalized artifact. There is no cross-tenant
--   cache: every key starts with tenant_id.
-- * tenant_ti_usage: per-minute and per-day request counters that enforce
--   the provider rate limits across API replicas (conditional upsert).
--
-- Bounds (API-enforced): 7 provider rows per tenant (one per official spec),
-- cache rows expire by TTL (max 30 days) and are pruned on write, usage rows
-- older than two days are pruned on write.
CREATE TABLE IF NOT EXISTS tenant_ti_providers (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider ~ '^[a-z0-9_]{1,64}$'),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    credentials_encrypted BYTEA,
    credentials_nonce TEXT,
    credential_fields TEXT[] NOT NULL DEFAULT '{}',
    per_minute INTEGER CHECK (per_minute BETWEEN 1 AND 600),
    per_day INTEGER CHECK (per_day BETWEEN 1 AND 200000),
    cache_ttl_secs INTEGER CHECK (cache_ttl_secs BETWEEN 300 AND 2592000),
    created_by UUID,
    updated_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, provider),
    CONSTRAINT tenant_ti_providers_sealed_pair
        CHECK ((credentials_encrypted IS NULL) = (credentials_nonce IS NULL))
);

CREATE TABLE IF NOT EXISTS tenant_ti_lookup_cache (
    tenant_id UUID NOT NULL,
    provider TEXT NOT NULL,
    artifact_type TEXT NOT NULL CHECK (artifact_type IN ('hash', 'domain', 'ip', 'url')),
    artifact_sha256 TEXT NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    artifact TEXT NOT NULL CHECK (length(artifact) BETWEEN 1 AND 2048),
    verdict TEXT NOT NULL CHECK (verdict IN ('malicious', 'suspicious', 'benign', 'unknown', 'not_found')),
    score SMALLINT CHECK (score BETWEEN 0 AND 100),
    result JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (octet_length(result::text) <= 16384),
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, provider, artifact_type, artifact_sha256),
    FOREIGN KEY (tenant_id, provider)
        REFERENCES tenant_ti_providers (tenant_id, provider) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tenant_ti_lookup_cache_expiry
    ON tenant_ti_lookup_cache (tenant_id, expires_at);

CREATE TABLE IF NOT EXISTS tenant_ti_usage (
    tenant_id UUID NOT NULL,
    provider TEXT NOT NULL,
    window_kind TEXT NOT NULL CHECK (window_kind IN ('minute', 'day')),
    window_start TIMESTAMPTZ NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    PRIMARY KEY (tenant_id, provider, window_kind, window_start),
    FOREIGN KEY (tenant_id, provider)
        REFERENCES tenant_ti_providers (tenant_id, provider) ON DELETE CASCADE
);
