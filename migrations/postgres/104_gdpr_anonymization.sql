-- GDPR Data Subject Anonymization
--
-- Tracks anonymization requests without retaining original PII.
-- The identifier_hash is an HMAC-SHA256 of the original value — the plaintext
-- is never persisted. Once executed, the anonymization is irreversible.

-- pgcrypto is needed for gen_random_bytes() (salt generation) and
-- digest() (SHA256 matching in user_registry anonymization)
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

-- Anonymization request tracking table
CREATE TABLE IF NOT EXISTS public.gdpr_anonymization_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identifier_type TEXT NOT NULL CHECK (identifier_type IN ('username', 'email', 'ip')),
    identifier_hash TEXT NOT NULL,  -- HMAC-SHA256 hash of the original identifier (plaintext never stored)
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    -- Per-table affected row counts (populated at submit time as estimates)
    logs_affected BIGINT NOT NULL DEFAULT 0,
    identity_observations_affected BIGINT NOT NULL DEFAULT 0,
    cloud_activity_affected BIGINT NOT NULL DEFAULT 0,
    user_registry_affected BIGINT NOT NULL DEFAULT 0,
    -- ClickHouse mutation tracking
    mutation_ids JSONB DEFAULT '[]'::jsonb,
    -- Justification and error context
    justification TEXT,
    error_message TEXT,
    -- User who requested this
    requested_by UUID NOT NULL REFERENCES public.users(id),
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_gdpr_anon_status ON public.gdpr_anonymization_requests(status);
CREATE INDEX idx_gdpr_anon_requested_by ON public.gdpr_anonymization_requests(requested_by);
CREATE INDEX idx_gdpr_anon_created_at ON public.gdpr_anonymization_requests(created_at DESC);

-- Per-deployment salt for HMAC-SHA256 anonymization (generated once, never rotated)
ALTER TABLE public.system_settings
    ADD COLUMN IF NOT EXISTS gdpr_anonymization_salt TEXT;

-- Generate salt on first migration (random 32 bytes, hex-encoded)
UPDATE public.system_settings
SET gdpr_anonymization_salt = encode(gen_random_bytes(32), 'hex')
WHERE id = 'default' AND gdpr_anonymization_salt IS NULL;

-- Register the gdpr:anonymize permission
INSERT INTO public.permissions (id, name, description, category)
VALUES ('gdpr:anonymize', 'gdpr:anonymize', 'Execute GDPR data subject anonymization', 'gdpr')
ON CONFLICT (id) DO NOTHING;

-- Grant gdpr:anonymize permission to Admin role
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, 'gdpr:anonymize'
FROM public.roles r
WHERE r.name = 'Admin'
ON CONFLICT (role_id, permission_id) DO NOTHING;
