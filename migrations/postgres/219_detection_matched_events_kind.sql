-- Audit D17 (NAN-1706): namespace detection_matched_events dedup by `kind`
-- (live bake-in vs alerting).
--
-- Before this, a rule with a lookback window that baked in Live and was then
-- promoted to Alerting had its FIRST real alert suppressed: the events recorded
-- during Live bake-in were still inside the lookback and the dedup filter (keyed
-- only on rule_id + event_id) removed them before the alert path ran. Splitting
-- the namespace so Live records can't suppress Alerting matches mirrors the
-- finding-emission dedup, which already namespaces live/alert.
--
-- Existing rows default to 'alert' so currently-alerting rules keep deduping
-- across the upgrade (no re-alert storm); the 7-day cleanup ages them out.

ALTER TABLE public.detection_matched_events
    ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'alert';

-- Repoint the primary key to include `kind`. The table is bounded by the 7-day
-- cleanup, so rebuilding the PK index is cheap.
ALTER TABLE public.detection_matched_events
    DROP CONSTRAINT IF EXISTS detection_matched_events_pkey;

ALTER TABLE public.detection_matched_events
    ADD CONSTRAINT detection_matched_events_pkey PRIMARY KEY (rule_id, kind, event_id);

COMMENT ON COLUMN public.detection_matched_events.kind IS
    'Dedup namespace: ''live'' (bake-in) or ''alert'' (alerting). Prevents Live bake-in records from suppressing the first Alerting alert after promotion (audit D17).';
