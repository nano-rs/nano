-- NAN-1305: cross-execution dedup for grouped / aggregate (| stats) detection findings.
--
-- Per-event rules dedup re-alerting via the single-event `event_hash`
-- (alerts.event_hash + ON CONFLICT), which gates both the alert and its finding.
-- Grouped / aggregate rules had no equivalent: each re-evaluation of an
-- overlapping lookback window (rule edit/enable, jobs restart/deploy, scheduler
-- gap) re-emitted one finding per entity unconditionally, doubling findings and
-- inflating entity risk scores for activity that was already alerted.
--
-- This table records each grouped finding emission keyed by
-- (rule_id, finding_hash), where finding_hash is derived from the aggregated
-- event window (_first_seen/_last_seen) + group entity rather than the
-- execution time. Re-evaluating the same entity over the same activity span
-- therefore collides and is suppressed. Genuinely new activity (a wider window
-- with later _last_seen) produces a new key and still emits.

CREATE TABLE IF NOT EXISTS public.detection_finding_emissions (
    rule_id uuid NOT NULL REFERENCES public.detection_rules(id) ON DELETE CASCADE,
    entity text NOT NULL,
    finding_hash text NOT NULL,
    window_end timestamp with time zone NOT NULL,
    emitted_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (rule_id, finding_hash)
);

COMMENT ON TABLE public.detection_finding_emissions IS
  'NAN-1305: records grouped/aggregate detection finding emissions keyed by (rule_id, finding_hash) so re-evaluating the same entity+window does not re-emit a finding or re-inflate entity risk.';

COMMENT ON COLUMN public.detection_finding_emissions.finding_hash IS
  'Stable cross-execution identity derived from rule + entity + aggregated event window (_first_seen/_last_seen), not the detection execution time.';

COMMENT ON COLUMN public.detection_finding_emissions.window_end IS
  'End of the aggregated event window (_last_seen) — the source-event time the finding is stamped with, used for retention.';

-- Retention: swept both by run_retention_now (settings/retention.rs) and by the
-- background `finding-emission-cleanup` task (state/cleanup.rs) via the function
-- below. Indexed on emitted_at for the time-bounded delete.
CREATE INDEX IF NOT EXISTS idx_detection_finding_emissions_emitted_at
    ON public.detection_finding_emissions USING btree (emitted_at);

-- 7-day retention mirrors cleanup_old_matched_events (migration 147): aligned
-- with MAX_LOOKBACK_MINUTES (10080 = 7 days), so dedup covers the full window a
-- rule can re-evaluate. Live-mode rules write here every run, so this needs an
-- actual scheduled sweep (unlike the dormant matched-events cleanup).
CREATE OR REPLACE FUNCTION public.cleanup_old_finding_emissions() RETURNS bigint
    LANGUAGE plpgsql
    AS $$
DECLARE
    removed bigint;
BEGIN
    DELETE FROM detection_finding_emissions
    WHERE emitted_at < NOW() - INTERVAL '7 days';
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END;
$$;
