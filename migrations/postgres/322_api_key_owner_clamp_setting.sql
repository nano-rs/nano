-- NAN-5044: API keys now run with their stored permissions CLAMPED to what the
-- owner holds at request time (a key minted before its owner was demoted no
-- longer keeps the old authority).
--
-- `enforce` (default) applies the clamp. `audit` keeps the stored set and only
-- logs what the clamp would withhold — a ONE-RELEASE escape hatch for an
-- automation outage right after the v2.0.1 upgrade, settable by an
-- administrator in Settings → Access control → API keys. It is scheduled for
-- removal in v2.1. Privilege administration (user/group/role grants) always
-- clamps, whatever this says.
--
-- Forward-only, additive, idempotent.
ALTER TABLE public.system_settings
    ADD COLUMN IF NOT EXISTS api_key_owner_clamp TEXT NOT NULL DEFAULT 'enforce';

DO $$
BEGIN
    ALTER TABLE public.system_settings
        ADD CONSTRAINT system_settings_api_key_owner_clamp_check
        CHECK (api_key_owner_clamp IN ('enforce', 'audit'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;
