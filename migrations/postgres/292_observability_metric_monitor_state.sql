-- NAN-4902 (lane A): durable per-series metric-monitor evaluation state.
--
-- The evaluator queries ClickHouse with NO PostgreSQL transaction open, then
-- applies the result in a short locked transaction. `evaluated_at` is the
-- per-(monitor, series) cursor that makes that safe: a result is applied only
-- when it is newer than the last one recorded, including a healthy result
-- that touched no incident. So a slow, older evaluation (e.g. across a jobs
-- leader failover) can never reopen an incident after a newer recovery.
--
-- Shape follows main's 372 `observability_metric_monitor_state` (NAN-3894)
-- for the single-tenant product: no tenant_id, keyed by (monitor_id,
-- series_key), cascading with the monitor definition. The O3b "last
-- evaluated / breaching / no data" read side can use this table as is.
CREATE TABLE IF NOT EXISTS public.observability_metric_monitor_state (
    monitor_id UUID NOT NULL
        REFERENCES public.observability_metric_monitors(id) ON DELETE CASCADE,
    series_key TEXT NOT NULL,
    value DOUBLE PRECISION,
    breaching BOOLEAN NOT NULL,
    no_data BOOLEAN NOT NULL,
    definition_updated_at TIMESTAMPTZ NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (monitor_id, series_key)
);

-- Bounds the per-evaluation incident lookups (open incidents of one monitor,
-- keyed by `<monitor>:<series>` source ids).
CREATE INDEX IF NOT EXISTS idx_alerts_observability_rearm
    ON public.alerts (kind, source_id, created_at DESC)
    WHERE kind IN ('metric_monitor', 'slo');
