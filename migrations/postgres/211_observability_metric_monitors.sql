-- NAN-1540: Metric monitors — threshold alerts on OTLP metric aggregates.
--
-- A monitor is a saved metrics-v2 query (metric_name + agg + optional group_by
-- + tag filters) plus a comparator/threshold and an evaluation cadence. The
-- panic-safe jobs runner ticks every `eval_interval_secs`: for each due enabled
-- monitor it runs the aggregate over the trailing `window_secs` window (one
-- scalar per series when `group_by` is set), compares each series value to
-- `threshold` via `comparator`, and on breach raises through the existing
-- alert/signal path. Like SLOs, the monitor *result* is NOT persisted here —
-- only the definition.
--
-- `filters` is the metrics-v2 tag-filter list: a JSON array of {key,value}
-- objects matched over the metric's attributes / resource_attributes maps.

CREATE TABLE IF NOT EXISTS observability_metric_monitors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Human label for the monitor (e.g. "p95 checkout latency > 500ms").
    name TEXT NOT NULL,
    -- The OTLP metric_name the monitor evaluates.
    metric_name TEXT NOT NULL,
    -- Aggregation applied over the window:
    -- avg|sum|min|max|count|rate|p50|p95|p99. Validated at the API layer.
    agg TEXT NOT NULL,
    -- Optional tag/attribute key to split into per-series evaluation. NULL = single series.
    group_by TEXT,
    -- Metrics-v2 tag filters: JSON array of {"key":..,"value":..} objects.
    filters JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- Breach test: aggregate value `comparator` threshold.
    comparator TEXT NOT NULL CHECK (comparator IN ('gt', 'gte', 'lt', 'lte')),
    threshold DOUBLE PRECISION NOT NULL,
    -- Trailing window (seconds) the aggregate is computed over each evaluation.
    window_secs INTEGER NOT NULL CHECK (window_secs >= 1),
    -- How often the runner evaluates the monitor (30s..1h).
    eval_interval_secs INTEGER NOT NULL CHECK (eval_interval_secs >= 30 AND eval_interval_secs <= 3600),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Runner scan: due enabled monitors, name-ordered for the console list.
CREATE INDEX IF NOT EXISTS idx_observability_metric_monitors_enabled
    ON observability_metric_monitors (enabled, metric_name);
