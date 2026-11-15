-- NAN-5424: a detection rule whose execution keeps failing for a reason other
-- than the window's size (NAN-4910) must neither pin its high-water mark
-- forever nor fail silently.
--
-- `consecutive_failures`: non-size, non-deterministic execution failures in a
-- row since the rule last succeeded. The scheduler retries the same window a
-- bounded number of times, then records the window in
-- `detection_coverage_gaps` and moves past it. Reset on success and once a gap
-- is recorded.
--
-- `failing_since`: when the current run of consecutive failures began (NULL
-- while the rule is healthy). Infrastructure failures (connection loss, the
-- scheduler's own timeout) only turn into a gap once the rule has been
-- failing for hours, so a short outage is still caught up rather than gapped.
--
-- `failure_class`: the class of the current streak (data / other /
-- transient / deterministic). A failure of a different class starts a new
-- streak, so budgets never mix.
--
-- `inflight_claims`: claims taken since the last release. A claim that is
-- reclaimed without ever being released (the executing process crashed or
-- was OOM-killed mid-run) is counted as a failed attempt.
--
-- `last_error` / `last_error_at`: the most recent execution or per-event
-- persistence error, REDACTED to the error class plus the ClickHouse code /
-- PostgreSQL SQLSTATE (database error text can quote event values; the full
-- text is only in the jobs log). Kept as history, not cleared on success;
-- surfaced through the rule API, the fleet-health rollup, `/health/detailed`
-- and SIEM Health. "Currently failing" is `consecutive_failures > 0`.
--
-- All streak counters are reset when the rule is edited.
ALTER TABLE public.detection_rules
    ADD COLUMN IF NOT EXISTS consecutive_failures SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS failing_since TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS failure_class TEXT,
    ADD COLUMN IF NOT EXISTS inflight_claims SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_error TEXT,
    ADD COLUMN IF NOT EXISTS last_error_at TIMESTAMPTZ;

-- A matched event that could not be persisted with its alert / match.
-- Durable evidence: the rule, the event's id and time, the window and the
-- PostgreSQL SQLSTATE — never the event's content. The event is not recorded
-- as matched, and a minimal reference alert is raised for it when possible.
CREATE TABLE IF NOT EXISTS public.detection_skipped_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID NOT NULL REFERENCES public.detection_rules(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL,
    event_timestamp TIMESTAMPTZ,
    window_start TIMESTAMPTZ,
    window_end TIMESTAMPTZ,
    sqlstate TEXT,
    error_class TEXT NOT NULL,
    reference_alert_id UUID,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT detection_skipped_events_rule_event UNIQUE (rule_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_detection_skipped_events_recorded_at
    ON public.detection_skipped_events (recorded_at DESC);

-- Health reads only rules with a recorded error.
CREATE INDEX IF NOT EXISTS idx_detection_rules_last_error_at
    ON public.detection_rules (last_error_at DESC)
    WHERE last_error_at IS NOT NULL;
