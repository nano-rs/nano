-- Detection-rule dataset targeting (NAN-1561)
--
-- Threads a `dataset` selector through the detection engine so a SCHEDULED
-- rule can run over the OTLP datasets in addition to UDM/OCSF logs:
--   * NULL / 'logs' — default (UDM/OCSF logs table); existing rows stay logs
--   * 'spans'        — OTLP spans (otel_spans)
--   * 'metrics'      — OTLP metrics (otel_metrics)
--
-- Spans/metrics are SCHEDULED-ONLY. The real-time materialized-view path
-- (detection/materialized_view.rs) reads FROM the logs table and assumes
-- UDM/OCSF physical columns, so it rejects any rule whose dataset is not
-- logs. Logs rules remain byte-identical.
--
-- Nullable with no default keeps every existing rule on the logs dataset.
ALTER TABLE detection_rules
    ADD COLUMN dataset TEXT NULL;

ALTER TABLE detection_rules
    ADD CONSTRAINT detection_rules_dataset_check
        CHECK (dataset IS NULL OR dataset IN ('logs', 'spans', 'metrics'));

COMMENT ON COLUMN detection_rules.dataset IS 'Query dataset: NULL/logs (default), spans, or metrics (NAN-1561). Spans/metrics are scheduled-only (rejected by the real-time materialized-view path).';
