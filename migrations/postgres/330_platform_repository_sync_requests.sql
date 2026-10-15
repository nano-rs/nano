-- NAN-2411: manual platform sync requests are durable and share the scheduled lease.
CREATE TABLE platform_repository_sync_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES enrichment_marketplace_repos(id) ON DELETE CASCADE,
    lease_token UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ,
    error TEXT
);
CREATE UNIQUE INDEX platform_repository_sync_requests_active
    ON platform_repository_sync_requests (repository_id) WHERE completed_at IS NULL;

CREATE TABLE platform_repository_sync_request_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    api_key_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX platform_repository_sync_request_audit_rate
    ON platform_repository_sync_request_audit (tenant_id, repository_id, created_at DESC);
