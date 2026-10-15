-- NAN-2361: bind pending MFA enrollment to the exact credential that created
-- it. Shared mode additionally binds the tenant UUID. Dedicated deployments
-- keep these nullable columns so the common logout/password-reset transaction
-- can safely cancel an in-progress setup without deployment-specific SQL.

ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS mfa_setup_authority_tenant_id UUID,
    ADD COLUMN IF NOT EXISTS mfa_setup_authority_jti UUID,
    ADD COLUMN IF NOT EXISTS mfa_setup_authority_authenticated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS mfa_setup_authority_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS mfa_setup_authority_is_challenge BOOLEAN;

COMMENT ON COLUMN public.users.mfa_setup_authority_jti IS
    'Exact enterprise_shared access/challenge JTI that owns the pending TOTP secret.';
COMMENT ON COLUMN public.users.mfa_setup_authority_authenticated_at IS
    'Immutable database-clock password/activation authentication fence for the pending MFA setup.';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'users_mfa_setup_authority_complete'
          AND conrelid = 'public.users'::regclass
    ) THEN
        ALTER TABLE public.users
            ADD CONSTRAINT users_mfa_setup_authority_complete CHECK (
                (mfa_setup_authority_tenant_id IS NULL
                 AND mfa_setup_authority_jti IS NULL
                 AND mfa_setup_authority_authenticated_at IS NULL
                 AND mfa_setup_authority_expires_at IS NULL
                 AND mfa_setup_authority_is_challenge IS NULL)
                OR
                (mfa_setup_authority_tenant_id IS NOT NULL
                 AND mfa_setup_authority_jti IS NOT NULL
                 AND mfa_setup_authority_authenticated_at IS NOT NULL
                 AND mfa_setup_authority_expires_at IS NOT NULL
                 AND mfa_setup_authority_is_challenge IS NOT NULL)
            );
    END IF;
END $$;
