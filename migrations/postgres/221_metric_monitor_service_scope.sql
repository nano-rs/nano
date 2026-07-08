-- NAN-1721 (O31): Metric-monitor service scope — thread the explorer's service
-- filter into the saved monitor.
--
-- The metrics explorer can scope a chart to a single OTLP service via the
-- promoted `otel_metrics.service_name` column (NAN-1564 — deliberately NOT a
-- tag/attribute filter). "Create monitor" previously dropped that scope, so a
-- monitor seeded from `| metric http.server.duration service=checkout`
-- evaluated the metric aggregated across ALL services (could fire on an
-- unrelated service or never fire for checkout). This column carries the scope
-- end-to-end so the runner's aggregate is restricted to the chosen service.
--
-- Nullable: NULL = fleet-wide (all services), preserving existing monitors'
-- behavior. The API layer trims empty strings to NULL. Matched against the
-- promoted `service_name` column by the metrics-v2 scalar SQL (`MetricQuery`).

ALTER TABLE observability_metric_monitors
    ADD COLUMN IF NOT EXISTS service_name TEXT;
