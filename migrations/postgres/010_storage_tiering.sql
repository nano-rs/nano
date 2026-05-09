-- Storage Tiering Configuration
-- Adds S3-compatible storage tiering columns to system_settings for ClickHouse data lifecycle management

-- Add tiering configuration columns to system_settings
ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS tiering_enabled boolean DEFAULT false NOT NULL,
ADD COLUMN IF NOT EXISTS tiering_s3_endpoint character varying(500),
ADD COLUMN IF NOT EXISTS tiering_s3_bucket character varying(255),
ADD COLUMN IF NOT EXISTS tiering_s3_region character varying(100) DEFAULT 'us-east-1',
ADD COLUMN IF NOT EXISTS tiering_s3_path_style boolean DEFAULT false NOT NULL,
ADD COLUMN IF NOT EXISTS tiering_s3_credentials_encrypted bytea,
ADD COLUMN IF NOT EXISTS tiering_s3_credentials_nonce character varying(32),
ADD COLUMN IF NOT EXISTS tiering_hot_days integer DEFAULT 30 NOT NULL,
ADD COLUMN IF NOT EXISTS tiering_warm_days integer DEFAULT 365 NOT NULL,
ADD COLUMN IF NOT EXISTS tiering_cold_enabled boolean DEFAULT false NOT NULL,
ADD COLUMN IF NOT EXISTS tiering_cold_days integer DEFAULT 730,
ADD COLUMN IF NOT EXISTS tiering_move_factor numeric(3,2) DEFAULT 0 NOT NULL,
ADD COLUMN IF NOT EXISTS tiering_status character varying(50) DEFAULT 'unconfigured',
ADD COLUMN IF NOT EXISTS tiering_status_message text,
ADD COLUMN IF NOT EXISTS tiering_last_applied_at timestamp with time zone;

-- Add constraints for tiering days validation (idempotent)
DO $$
BEGIN
    -- Hot days: 1-365 days
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'tiering_hot_days_check'
    ) THEN
        ALTER TABLE public.system_settings
        ADD CONSTRAINT tiering_hot_days_check
            CHECK (tiering_hot_days >= 1 AND tiering_hot_days <= 365);
    END IF;

    -- Warm days: must be greater than hot days, up to 10 years
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'tiering_warm_days_check'
    ) THEN
        ALTER TABLE public.system_settings
        ADD CONSTRAINT tiering_warm_days_check
            CHECK (tiering_warm_days > tiering_hot_days AND tiering_warm_days <= 3650);
    END IF;

    -- Cold days: must be greater than warm days (when set)
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'tiering_cold_days_check'
    ) THEN
        ALTER TABLE public.system_settings
        ADD CONSTRAINT tiering_cold_days_check
            CHECK (tiering_cold_days IS NULL OR tiering_cold_days > tiering_warm_days);
    END IF;

    -- Move factor: 0 to 1 (0 = disabled, 0.1 = move when 90% full)
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'tiering_move_factor_check'
    ) THEN
        ALTER TABLE public.system_settings
        ADD CONSTRAINT tiering_move_factor_check
            CHECK (tiering_move_factor >= 0 AND tiering_move_factor <= 1);
    END IF;
END $$;

-- Comments for documentation
COMMENT ON COLUMN public.system_settings.tiering_enabled IS 'Whether S3 storage tiering is enabled for ClickHouse logs';
COMMENT ON COLUMN public.system_settings.tiering_s3_endpoint IS 'Custom S3 endpoint URL for S3-compatible storage (MinIO, R2, B2). Leave NULL for AWS S3.';
COMMENT ON COLUMN public.system_settings.tiering_s3_bucket IS 'S3 bucket name for tiered storage';
COMMENT ON COLUMN public.system_settings.tiering_s3_region IS 'AWS region or S3-compatible region identifier';
COMMENT ON COLUMN public.system_settings.tiering_s3_path_style IS 'Use path-style access (required for MinIO and some S3-compatible services)';
COMMENT ON COLUMN public.system_settings.tiering_s3_credentials_encrypted IS 'AES-256-GCM encrypted S3 credentials JSON (access_key_id, secret_access_key)';
COMMENT ON COLUMN public.system_settings.tiering_s3_credentials_nonce IS 'Base64-encoded nonce for credential decryption';
COMMENT ON COLUMN public.system_settings.tiering_hot_days IS 'Days to keep data on local hot storage (fast SSD). Default: 30';
COMMENT ON COLUMN public.system_settings.tiering_warm_days IS 'Total days before data is deleted (includes hot + warm). Data moves to S3 after hot_days. Default: 365';
COMMENT ON COLUMN public.system_settings.tiering_cold_enabled IS 'Whether to export data to cold archive before deletion';
COMMENT ON COLUMN public.system_settings.tiering_cold_days IS 'Days to retain cold archive data. Default: 730 (2 years)';
COMMENT ON COLUMN public.system_settings.tiering_move_factor IS 'Automatic move factor: 0 = TTL-only moves, 0.1 = move when disk is 90% full. Default: 0';
COMMENT ON COLUMN public.system_settings.tiering_status IS 'Current tiering status: unconfigured, pending, applying, active, error';
COMMENT ON COLUMN public.system_settings.tiering_status_message IS 'Status message or error description';
COMMENT ON COLUMN public.system_settings.tiering_last_applied_at IS 'Timestamp when tiering config was last applied to ClickHouse';
