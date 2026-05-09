-- Organizational Context Configuration
-- Adds columns to system_settings for user-defined organizational context
-- that is injected into meloD AI prompts to provide relevant, tailored responses

-- Add organizational context columns to system_settings
ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS org_context_name text,
ADD COLUMN IF NOT EXISTS org_context_industry text,
ADD COLUMN IF NOT EXISTS org_context_environment text,
ADD COLUMN IF NOT EXISTS org_context_attack_vectors text,
ADD COLUMN IF NOT EXISTS org_context_compliance text[] DEFAULT '{}',
ADD COLUMN IF NOT EXISTS org_context_custom text,
ADD COLUMN IF NOT EXISTS org_context_enable_chat boolean DEFAULT true NOT NULL,
ADD COLUMN IF NOT EXISTS org_context_enable_query boolean DEFAULT true NOT NULL,
ADD COLUMN IF NOT EXISTS org_context_enable_detection boolean DEFAULT true NOT NULL,
ADD COLUMN IF NOT EXISTS org_context_enable_parser boolean DEFAULT true NOT NULL,
ADD COLUMN IF NOT EXISTS org_context_enable_dashboard boolean DEFAULT true NOT NULL;

-- Comments for documentation
COMMENT ON COLUMN public.system_settings.org_context_name IS 'Organization or team name for context in AI prompts';
COMMENT ON COLUMN public.system_settings.org_context_industry IS 'Industry vertical (e.g., Financial Services, Healthcare, Technology)';
COMMENT ON COLUMN public.system_settings.org_context_environment IS 'Environment details: tools, platforms, and technologies in use (e.g., Apache, IIS, CrowdStrike)';
COMMENT ON COLUMN public.system_settings.org_context_attack_vectors IS 'Top attack vectors of concern (e.g., ransomware, phishing, insider threats)';
COMMENT ON COLUMN public.system_settings.org_context_compliance IS 'Compliance frameworks applicable to the organization (e.g., PCI-DSS, HIPAA, SOC2)';
COMMENT ON COLUMN public.system_settings.org_context_custom IS 'Additional custom context to include in AI prompts';
COMMENT ON COLUMN public.system_settings.org_context_enable_chat IS 'Apply organizational context to chat assistant';
COMMENT ON COLUMN public.system_settings.org_context_enable_query IS 'Apply organizational context to query builder';
COMMENT ON COLUMN public.system_settings.org_context_enable_detection IS 'Apply organizational context to detection rule creator';
COMMENT ON COLUMN public.system_settings.org_context_enable_parser IS 'Apply organizational context to log parser generator';
COMMENT ON COLUMN public.system_settings.org_context_enable_dashboard IS 'Apply organizational context to dashboard generator';
