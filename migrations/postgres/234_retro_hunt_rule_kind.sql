-- NAN-1791: Auto retro-hunt on new threat-intel indicators.
--
-- A retro-hunt rule is a first-class detection rule (kind = 'retro_hunt') that,
-- on its schedule, computes the DELTA of newly-landed feed indicators and hunts
-- them over historical logs via the retro engine, emitting hits through the
-- STANDARD signal processor -> alerts path (case grouping / dedup / risk reuse).
--
-- This migration adds the `kind` discriminator to detection_rules and the
-- per-rule retro-hunt configuration table. State (watermark, hunted indicators)
-- and run history live in the following two migrations (235, 236).

-- 1. Discriminator column on detection_rules. Defaults to 'standard' so every
--    existing rule is unchanged and the `SELECT *` row mapping keeps working.
ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'standard';

-- Constrain the discriminator to the known values. Guarded so a re-run (or a
-- reconciled checksum) never errors on the already-present constraint.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'detection_rules_kind_check'
    ) THEN
        ALTER TABLE detection_rules
            ADD CONSTRAINT detection_rules_kind_check
            CHECK (kind IN ('standard', 'retro_hunt'));
    END IF;
END $$;

-- Partial index for listing the (few) non-standard rules without scanning the
-- whole table.
CREATE INDEX IF NOT EXISTS idx_detection_rules_kind
    ON detection_rules (kind)
    WHERE kind <> 'standard';

-- 2. Per-rule retro-hunt configuration. One row per retro-hunt rule; deleted
--    with the rule via ON DELETE CASCADE.
--
--    * feeds           - selected feed names (enrichment_name); empty = ALL feeds.
--    * artifact_types  - ip/domain/hash/url filter; empty = ALL types.
--    * lookback_days   - how far back the retro hunt scans (1..365).
--    * max_indicators_per_run - hard per-run cap; overflow is carried to the
--                        next run (bounded by the retro engine's own 1000 cap).
CREATE TABLE IF NOT EXISTS retro_hunt_rule_config (
    rule_id                 UUID PRIMARY KEY REFERENCES detection_rules(id) ON DELETE CASCADE,
    feeds                   TEXT[]      NOT NULL DEFAULT '{}',
    artifact_types          TEXT[]      NOT NULL DEFAULT '{}',
    lookback_days           INT         NOT NULL DEFAULT 90,
    max_indicators_per_run  INT         NOT NULL DEFAULT 500,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT retro_hunt_lookback_days_bounds
        CHECK (lookback_days BETWEEN 1 AND 365),
    CONSTRAINT retro_hunt_max_indicators_bounds
        CHECK (max_indicators_per_run BETWEEN 1 AND 1000)
);
