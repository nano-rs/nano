-- NAN-535: Wire up credential versions/rotate, env tag, expires_at, last_used_at
--
-- Adds environment + expires_at + last_used_at + active_version metadata to
-- cloud_credentials, plus a cloud_credential_versions table that holds the full
-- history of encrypted payloads for rotation and rollback.
--
-- Strategy: the parent cloud_credentials row keeps its credentials_encrypted +
-- nonce columns as a denormalized mirror of the active version's payload, so
-- the existing decryption path in parsers/service/credentials.rs continues to
-- work unchanged. Rotate/rollback updates both the version row and the parent
-- mirror in a single transaction.

-- ---------------------------------------------------------------------------
-- 1. Extend cloud_credentials with the new metadata columns.
-- ---------------------------------------------------------------------------

ALTER TABLE public.cloud_credentials
    ADD COLUMN environment varchar(20),
    ADD COLUMN expires_at timestamptz,
    ADD COLUMN last_used_at timestamptz,
    ADD COLUMN active_version integer NOT NULL DEFAULT 1;

ALTER TABLE public.cloud_credentials
    ADD CONSTRAINT cloud_credentials_environment_check
    CHECK (environment IS NULL OR environment IN ('prod', 'staging', 'dev'));

COMMENT ON COLUMN public.cloud_credentials.environment IS
    'Optional environment tag — one of prod / staging / dev';
COMMENT ON COLUMN public.cloud_credentials.expires_at IS
    'Optional rotation deadline; drives the Health badge in the UI';
COMMENT ON COLUMN public.cloud_credentials.last_used_at IS
    'Timestamp of the most recent decrypt-for-deploy; updated by ParserService';
COMMENT ON COLUMN public.cloud_credentials.active_version IS
    'Version number currently mirrored into credentials_encrypted/nonce; matches cloud_credential_versions.version_number where is_active = true';

-- ---------------------------------------------------------------------------
-- 2. Versions table — full history of encrypted payloads.
-- ---------------------------------------------------------------------------

CREATE TABLE public.cloud_credential_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    credential_id uuid NOT NULL REFERENCES public.cloud_credentials(id) ON DELETE CASCADE,
    version_number integer NOT NULL,

    -- Encrypted payload (same shape as cloud_credentials.credentials_encrypted)
    credentials_encrypted bytea NOT NULL,
    nonce varchar(32) NOT NULL,

    -- Audit
    created_at timestamptz DEFAULT now() NOT NULL,
    created_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
    note text,

    -- One active version per credential (enforced by partial unique index below)
    is_active boolean NOT NULL DEFAULT false,

    -- Set when this version was created via rollback; points at the version we copied from
    reverted_from_version integer,

    CONSTRAINT cloud_credential_versions_pkey PRIMARY KEY (id),
    CONSTRAINT cloud_credential_versions_unique_version UNIQUE (credential_id, version_number)
);

CREATE INDEX idx_cloud_credential_versions_credential
    ON public.cloud_credential_versions(credential_id);

-- At most one active version per credential
CREATE UNIQUE INDEX idx_cloud_credential_versions_active
    ON public.cloud_credential_versions(credential_id)
    WHERE is_active;

COMMENT ON TABLE public.cloud_credential_versions IS
    'Full history of encrypted payloads for each cloud credential — supports rotate + rollback';
COMMENT ON COLUMN public.cloud_credential_versions.is_active IS
    'Exactly one row per credential has is_active = true; that row''s payload is mirrored into cloud_credentials.credentials_encrypted/nonce';
COMMENT ON COLUMN public.cloud_credential_versions.reverted_from_version IS
    'Set when this row was created by a rollback; points at the version_number we copied the payload from';

-- ---------------------------------------------------------------------------
-- 3. Backfill: each existing cloud_credentials row gets a v1 in the versions
--    table copying its current payload, marked active.
-- ---------------------------------------------------------------------------

INSERT INTO public.cloud_credential_versions
    (credential_id, version_number, credentials_encrypted, nonce, created_at, created_by, note, is_active)
SELECT
    id,
    1,
    credentials_encrypted,
    nonce,
    created_at,
    created_by,
    'Backfilled from cloud_credentials at NAN-535 migration',
    true
FROM public.cloud_credentials
ON CONFLICT (credential_id, version_number) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 4. New permission: credentials:rotate (separate from edit since rotation
--    replaces the secret material, not just metadata).
-- ---------------------------------------------------------------------------

INSERT INTO public.permissions (id, name, description, category) VALUES
    ('credentials:rotate', 'Rotate Credentials', 'Rotate or rollback the secret material on a cloud credential', 'credentials')
ON CONFLICT (id) DO NOTHING;

-- Grant to Admin role only (rotation is privileged — secret material changes
-- and downstream source configs pick up the new secret on next deploy).
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001'::uuid, p.id
FROM public.permissions p
WHERE p.id = 'credentials:rotate'
ON CONFLICT DO NOTHING;
