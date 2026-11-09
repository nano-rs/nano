-- NAN-5055: AI allowance granted by an admitted online licence check-in
-- (an audited nano-main deployment entitlement grant, e.g. a grandfathered
-- original managed tenant). NULL means no grant: the provisioned
-- NANO_AI_CREDITS_PER_MONTH ceiling applies as before. Only the online
-- licence checker writes it, and boot clears it whenever online licensing is
-- not the admission authority. Forward-only and idempotent; no backfill.
ALTER TABLE system_settings
    ADD COLUMN IF NOT EXISTS entitlement_ai_credits_per_month INTEGER;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'check_entitlement_ai_credits_per_month'
          AND conrelid = 'system_settings'::regclass
    ) THEN
        ALTER TABLE system_settings
            ADD CONSTRAINT check_entitlement_ai_credits_per_month
            CHECK (
                entitlement_ai_credits_per_month IS NULL
                OR entitlement_ai_credits_per_month > 0
            );
    END IF;
END $$;

COMMENT ON COLUMN system_settings.entitlement_ai_credits_per_month IS
    'monthly AI credits granted by the online licence check-in; NULL = provisioned env ceiling';
