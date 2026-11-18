-- NAN-5577: allow 'hunt_finding' on the unified alert spine.
--
-- A case promoted from a hunt finding (by an analyst, or by the hunt
-- reviewer's policy B) carries the finding's evidence events on ONE alert of
-- kind = 'hunt_finding' (rule_id NULL, source_id = the lead TypeID 'lead_...').
-- That alert is what the case's event count, alert strip and per-source
-- visibility read: its source_types is the LEAD's source manifest (plus the
-- unresolved-provenance sentinel when that manifest is incomplete), and
-- case_source_predicate treats a hunt-finding alert the reader is denied as
-- hiding the whole case (even when other linked alerts are visible), so a
-- reader denied the finding is denied the case and its notebook.
--
-- The SIEM Alerts page lists kinds 'detection' and 'risk_notable' only, so
-- these alerts appear on their case, not in the alert queue.
--
-- Same shape as 237: the migration-212 CHECK enumerates allowed kinds, so
-- widen it. Open-core deployments never insert this kind (hunts are
-- enterprise-only) but share the schema; the widened CHECK is harmless there.
-- Forward-only and idempotent: re-running drops and re-adds the same CHECK.
ALTER TABLE public.alerts DROP CONSTRAINT IF EXISTS alerts_kind_check;
ALTER TABLE public.alerts
    ADD CONSTRAINT alerts_kind_check
    CHECK (kind IN ('detection', 'metric_monitor', 'slo', 'synthetic', 'risk_notable', 'hunt_finding'));

-- One hunt-finding alert per lead: the seeding path's idempotency key, and the
-- index its probe (kind + source_id) uses.
CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_hunt_finding_source
    ON public.alerts (source_id) WHERE kind = 'hunt_finding';
