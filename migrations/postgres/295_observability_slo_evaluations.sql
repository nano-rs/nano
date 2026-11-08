-- NAN-4902 (lane F): durable SLO evaluation state (O3b, main's 372 NAN-3894).
--
-- The dedicated SLO scheduler records its latest result per SLO each tick so
-- the console can say "last evaluated N s ago · ok / breaching / no data /
-- partial" and so alerting and the read path agree on one number. Definitions
-- stay the source of truth: a row is only shown while `definition_updated_at`
-- matches the SLO's `updated_at` (an edit invalidates the cached result).
--
-- `status = 'partial'` means the target service's telemetry does not cover the
-- whole window (first seen inside it, or a gap longer than the tolerance): the
-- evaluator then stores no attainment / budget / burn and never alerts.
--
-- Shape follows main's 372 `observability_slo_evaluations` for the
-- single-tenant product: no tenant_id, keyed by slo_id, cascading with the
-- definition. burn_fast/burn_slow keep main's columns; the single-window
-- evaluator writes the window burn rate to both. The metric-monitor half of
-- 372 (and the rearm index) shipped in 292.
CREATE TABLE IF NOT EXISTS public.observability_slo_evaluations (
    slo_id UUID PRIMARY KEY
        REFERENCES public.observability_slos(id) ON DELETE CASCADE,
    current DOUBLE PRECISION,
    total BIGINT NOT NULL CHECK (total >= 0),
    no_data BOOLEAN NOT NULL,
    budget_remaining_pct DOUBLE PRECISION,
    burn_fast DOUBLE PRECISION,
    burn_slow DOUBLE PRECISION,
    status TEXT NOT NULL
        CHECK (status IN ('ok', 'at_risk', 'breaching', 'no_data', 'partial')),
    definition_updated_at TIMESTAMPTZ NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL
);

-- Monitor-wide evaluation generation (NAN-4902 lane F review). Every result
-- set a metric-monitor evaluation applies — including an EMPTY one —
-- advances this one row first, inside the per-monitor lock. A result set
-- older than (or equal to) the recorded generation is dropped whole, so an
-- older evaluation can never write a series cursor or open / update /
-- resolve an incident after a newer evaluation landed (e.g. a slow leader's
-- `node-a` breach after a newer empty result). The per-series cursor in 292
-- stays as a second fence. The console serves only the series rows of the
-- current generation.
CREATE TABLE IF NOT EXISTS public.observability_metric_monitor_generation (
    monitor_id UUID PRIMARY KEY
        REFERENCES public.observability_metric_monitors(id) ON DELETE CASCADE,
    evaluated_at TIMESTAMPTZ NOT NULL
);
