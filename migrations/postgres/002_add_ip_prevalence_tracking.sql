-- Add IP prevalence tracking setting
-- This enables tracking of IP address prevalence similar to hash and domain tracking

ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS prevalence_enable_ip_tracking boolean DEFAULT true NOT NULL;

COMMENT ON COLUMN public.system_settings.prevalence_enable_ip_tracking IS 'Whether to track IP address prevalence (default: true)';
