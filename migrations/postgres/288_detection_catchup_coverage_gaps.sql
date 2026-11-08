-- NAN-4910 (port of NAN-2564 to the single-tenant ClickHouse edition):
-- detection catch-up must never silently drop coverage.
--
-- The distributed scheduler used to floor a catch-up window at
-- `now - max_catchup_minutes` (24 h), so after any scheduler / detection outage
-- longer than that the older interval was skipped and never evaluated. It now
-- works a backlog oldest-first in bounded slices from `last_run_at`. A slice
-- that fails for an explicit ClickHouse SIZE-limit reason (memory limit, too
-- many rows / bytes, oversized response, server-side max_execution_time with
-- elapsed time) is retried smaller — the scheduler's generic outer timeout and
-- connection errors are NOT size failures and never create a gap; when even the minimum slice
-- keeps failing, the slice is recorded here as a coverage gap and the rule moves
-- past it instead of pinning on the same window forever.
--
-- `catchup_size_failures`: consecutive size-class failures of a marker-driven
-- rule since its last successful slice; it selects the shrinking slice size and
-- is reset on success or once a gap is recorded.
ALTER TABLE public.detection_rules
    ADD COLUMN IF NOT EXISTS catchup_size_failures SMALLINT NOT NULL DEFAULT 0;

-- One row per detection window that could not be evaluated. Read by SIEM
-- health (detection dimension) so an unevaluated interval is visible, and by
-- operators to replay the exact window by hand.
CREATE TABLE IF NOT EXISTS public.detection_coverage_gaps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID NOT NULL REFERENCES public.detection_rules(id) ON DELETE CASCADE,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL,
    error_message TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT detection_coverage_gaps_window_order CHECK (window_start < window_end)
);

CREATE INDEX IF NOT EXISTS idx_detection_coverage_gaps_recorded_at
    ON public.detection_coverage_gaps (recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_detection_coverage_gaps_rule
    ON public.detection_coverage_gaps (rule_id, window_start);
