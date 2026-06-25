-- NAN-1541: Unified alert spine.
--
-- Security detections and observability monitors (metric_monitor / slo /
-- synthetic) keep SEPARATE definition models + evaluators, but FIRE into ONE
-- spine: the `alerts` table and everything hanging off it (notification +
-- incident path, the console alert views). To let a single table carry both
-- worlds without merging their definitions, we add a discriminator.
--
-- `kind`      — what produced this alert. Defaults to 'detection' so every
--               existing row (and every untouched detection insert) keeps its
--               historical meaning with no backfill.
-- `source_id` — the producer's identifier as TEXT: the detection rule UUID for
--               'detection' rows, or the monitor/check typeid for observability
--               rows. TEXT (not UUID) because observability ids are typeids and
--               detection rule ids are UUIDs — one column holds both.
--
-- `rule_id` is already nullable (the FK is ON DELETE SET NULL — NAN-1356), so
-- no nullability change is required; observability rows leave it NULL.

ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'detection'
        CONSTRAINT alerts_kind_check
        CHECK (kind IN ('detection', 'metric_monitor', 'slo', 'synthetic'));

ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS source_id TEXT;

-- Existing detection rows: stamp source_id from the rule_id so the spine has a
-- consistent producer reference even for pre-212 alerts.
UPDATE public.alerts
    SET source_id = rule_id::text
    WHERE source_id IS NULL AND rule_id IS NOT NULL;

-- The console filters alerts by kind on every load (SIEM Alerts => detection,
-- Observability Alerts => the three monitor kinds), so index the discriminator.
CREATE INDEX IF NOT EXISTS idx_alerts_kind ON public.alerts (kind);
