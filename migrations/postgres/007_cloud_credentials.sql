-- Cloud storage credentials for parser sources (AWS S3, Azure Blob, etc.)
-- Credentials are encrypted using AES-256-GCM before storage

CREATE TABLE public.cloud_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    provider character varying(50) NOT NULL,  -- 'aws_s3' or 'azure_blob'

    -- Encrypted credential blob (JSON serialized, then AES-GCM encrypted)
    credentials_encrypted bytea NOT NULL,
    nonce character varying(32) NOT NULL,  -- Base64 encoded 12-byte nonce

    -- Metadata (unencrypted, for display/selection)
    description text,
    region character varying(100),  -- AWS region or Azure location

    -- Audit
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid REFERENCES public.users(id) ON DELETE SET NULL,

    CONSTRAINT cloud_credentials_pkey PRIMARY KEY (id),
    CONSTRAINT cloud_credentials_name_key UNIQUE (name),
    CONSTRAINT cloud_credentials_provider_check CHECK (provider IN ('aws_s3', 'azure_blob'))
);

-- Index for quick credential lookup by provider
CREATE INDEX idx_cloud_credentials_provider ON public.cloud_credentials(provider);

-- Updated_at trigger
CREATE TRIGGER trigger_cloud_credentials_updated_at
    BEFORE UPDATE ON public.cloud_credentials
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- Link parsers to credentials (nullable for backward compatibility)
ALTER TABLE public.parsers
ADD COLUMN credential_id uuid REFERENCES public.cloud_credentials(id) ON DELETE SET NULL;

-- Index for finding parsers using a credential
CREATE INDEX idx_parsers_credential_id ON public.parsers(credential_id) WHERE credential_id IS NOT NULL;

-- Permissions for credential management
INSERT INTO public.permissions (id, name, description, category) VALUES
    ('credentials:view', 'View Credentials', 'View cloud storage credentials', 'credentials'),
    ('credentials:create', 'Create Credentials', 'Create new cloud storage credentials', 'credentials'),
    ('credentials:edit', 'Edit Credentials', 'Modify cloud storage credentials', 'credentials'),
    ('credentials:delete', 'Delete Credentials', 'Remove cloud storage credentials', 'credentials')
ON CONFLICT (id) DO NOTHING;

-- Grant all credential permissions to Admin role
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r, public.permissions p
WHERE r.id = '00000000-0000-0000-0000-000000000001'  -- Admin role UUID
  AND p.id IN ('credentials:view', 'credentials:create', 'credentials:edit', 'credentials:delete')
ON CONFLICT DO NOTHING;

-- Grant view permission to Editor role
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000002'::uuid, p.id
FROM public.permissions p
WHERE p.id = 'credentials:view'
ON CONFLICT DO NOTHING;

-- Grant view permission to Analyst role
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000003'::uuid, p.id
FROM public.permissions p
WHERE p.id = 'credentials:view'
ON CONFLICT DO NOTHING;

COMMENT ON TABLE public.cloud_credentials IS 'Encrypted storage for cloud provider credentials (AWS S3, Azure Blob)';
COMMENT ON COLUMN public.cloud_credentials.credentials_encrypted IS 'AES-256-GCM encrypted JSON containing provider-specific credentials';
COMMENT ON COLUMN public.cloud_credentials.nonce IS 'Base64-encoded 12-byte nonce used for AES-GCM encryption';
COMMENT ON COLUMN public.cloud_credentials.provider IS 'Cloud provider type: aws_s3 or azure_blob';
