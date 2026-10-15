-- NAN-3580 PR3: durable pins survive export disable, freeze and credential revoke.
CREATE TABLE public.iceberg_hosted_tables (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    table_key TEXT NOT NULL CHECK (length(table_key) BETWEEN 1 AND 300),
    binding JSONB NOT NULL CHECK (jsonb_typeof(binding)='object' AND octet_length(binding::text)<=16384),
    pending_manifest JSONB CHECK (jsonb_typeof(pending_manifest)='object' AND octet_length(pending_manifest::text)<=16777216),
    last_plan_ms BIGINT CHECK (last_plan_ms>0),
    last_success TIMESTAMPTZ,
    PRIMARY KEY(tenant_id,table_key)
);
-- Permanent fences: never prune while any export contract can bootstrap/retry.
CREATE TABLE public.iceberg_hosted_retired_parts (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    part_id TEXT NOT NULL CHECK (part_id ~ '^[0-9]{13}-[0-9a-f]{16}$'),
    retired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(tenant_id,part_id)
);
CREATE TABLE public.iceberg_hosted_read_credentials (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id UUID NOT NULL,
    token_sha256 TEXT NOT NULL CHECK (token_sha256 ~ '^[0-9a-f]{64}$'),
    credentials_encrypted BYTEA CHECK (octet_length(credentials_encrypted)<=32768),
    credentials_nonce TEXT CHECK (length(credentials_nonce)<=64),
    active BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(tenant_id,id),
    CHECK ((credentials_encrypted IS NULL)=(credentials_nonce IS NULL)),
    CONSTRAINT hosted_reads_require_cost_guard CHECK (NOT active)
);
