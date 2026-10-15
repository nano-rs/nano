-- Spot-safe pointer and lease authority for node-local lake sidecar caches.
-- Large bytes remain content-addressed in object storage; this row is the
-- only mutable head.  A delayed holder can advance it only with the exact
-- renewable lease token and starting revision it acquired.

CREATE TABLE IF NOT EXISTS lake_authoritative_state (
    tenant_id TEXT NOT NULL,
    security_tenant_id UUID NOT NULL,
    state_kind TEXT NOT NULL CHECK (
        state_kind IN ('risk', 'enrichment')
    ),
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    envelope_key TEXT,
    envelope_sha256 TEXT,
    envelope_bytes BIGINT,
    lease_owner TEXT,
    lease_token UUID,
    lease_expires_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (security_tenant_id, state_kind),
    UNIQUE (security_tenant_id, tenant_id, state_kind),
    CHECK (length(tenant_id) BETWEEN 1 AND 256),
    CHECK (
        (revision = 0 AND envelope_key IS NULL AND envelope_sha256 IS NULL AND envelope_bytes IS NULL)
        OR (
            revision > 0
            AND envelope_key IS NOT NULL AND length(envelope_key) BETWEEN 1 AND 2048
            AND envelope_sha256 ~ '^[0-9a-f]{64}$'
            AND envelope_bytes BETWEEN 1 AND 1048576
        )
    ),
    CHECK (
        (lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
        OR (
            lease_owner IS NOT NULL AND length(lease_owner) BETWEEN 1 AND 256
            AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_lake_authoritative_state_expired_lease
    ON lake_authoritative_state (lease_expires_at)
    WHERE lease_token IS NOT NULL;

COMMENT ON TABLE lake_authoritative_state IS
    'Token-fenced PostgreSQL head for content-addressed risk and enrichment state; local files are caches only.';
