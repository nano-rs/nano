-- v2 entitlement identity.
--
-- Product features are selected by the open/enterprise build boundary, not
-- by a named pricing plan.  Licensed capacity is independent metadata in
-- decimal GB/day, and operator controls only who supplies the AI allowance.
-- The old tier columns remain for an N-1 rolling peer; canonical writes set
-- them to the former full-feature `unrestricted` representation.

ALTER TABLE system_settings
    ADD COLUMN IF NOT EXISTS entitlement_edition TEXT,
    ADD COLUMN IF NOT EXISTS entitlement_operator TEXT,
    ADD COLUMN IF NOT EXISTS entitlement_capacity_gb_per_day NUMERIC;

-- Backfill once.  Retired paid tier names become licensed and preserve their
-- historical GB/day number solely as capacity metadata.  `unrestricted` was
-- the pre-v2 default for unlicensed/community installs, so boot reconciliation
-- makes the authoritative build-specific choice after migration.
UPDATE system_settings
SET entitlement_edition = CASE
        WHEN tier = 'unrestricted' THEN 'open'
        ELSE 'licensed'
    END,
    entitlement_operator = 'self-run',
    entitlement_capacity_gb_per_day = CASE tier
        WHEN 'hobby' THEN 2
        WHEN 'startup' THEN 5
        WHEN 'growth' THEN 10
        WHEN 'team' THEN 25
        WHEN 'starter' THEN 50
        WHEN 'pro' THEN 100
        ELSE tier_max_daily_gb
    END
WHERE entitlement_edition IS NULL;

ALTER TABLE system_settings
    ALTER COLUMN entitlement_edition SET DEFAULT 'open',
    ALTER COLUMN entitlement_edition SET NOT NULL,
    ALTER COLUMN entitlement_operator SET DEFAULT 'self-run',
    ALTER COLUMN entitlement_operator SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'check_entitlement_edition'
          AND conrelid = 'system_settings'::regclass
    ) THEN
        ALTER TABLE system_settings
            ADD CONSTRAINT check_entitlement_edition
            CHECK (entitlement_edition IN ('open', 'licensed'));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'check_entitlement_operator'
          AND conrelid = 'system_settings'::regclass
    ) THEN
        ALTER TABLE system_settings
            ADD CONSTRAINT check_entitlement_operator
            CHECK (entitlement_operator IN ('self-run', 'hosted'));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'check_entitlement_capacity_gb_per_day'
          AND conrelid = 'system_settings'::regclass
    ) THEN
        ALTER TABLE system_settings
            ADD CONSTRAINT check_entitlement_capacity_gb_per_day
            CHECK (
                entitlement_capacity_gb_per_day IS NULL
                OR entitlement_capacity_gb_per_day > 0
            );
    END IF;
END $$;

COMMENT ON COLUMN system_settings.entitlement_edition IS
    'v2 product edition: open or licensed';
COMMENT ON COLUMN system_settings.entitlement_operator IS
    'v2 operator: self-run or hosted; controls nano-provided AI allowance only';
COMMENT ON COLUMN system_settings.entitlement_capacity_gb_per_day IS
    'contracted decimal GB/day capacity; never a feature selector';
