-- Migration: collector error channel (NAN-2196).
--
-- WHY THIS EXISTS
-- ---------------
-- `LogSourceHealth` was entirely volume-based — event counts, timestamps, and a
-- status derived from throughput. It had no channel for "the collector is
-- failing", so a source that is broken and a source that is merely quiet were
-- literally the same object in the API. The only way to learn WHY ingest was
-- broken was `docker logs nanosiem-vector`, which no customer will do and which
-- is unavailable in a managed deployment.
--
-- Vector already collects this. `config/vector/92-metrics.toml` has had an
-- `internal_logs` source and a `filter_internal_logs` transform keeping only
-- WARN/ERROR since long before this migration. Those events were written to a
-- console sink — Docker stdout — and thrown away. This table is where they land
-- instead.
--
-- THE EVENT SHAPE  (verified against Vector 0.56.0, not inferred)
-- ---------------------------------------------------------------
-- A failing `aws_s3` source emits exactly this, which is the schema below:
--
--   {"message":"Failed to fetch SQS events.",
--    "error_code":"failed_fetching_sqs_events",
--    "error_type":"request_failed",
--    "stage":"receiving",
--    "metadata":{"level":"ERROR", ...},
--    "vector":{"component_id":"aws_alb_source",
--              "component_kind":"source",
--              "component_type":"aws_s3"}}
--
-- `vector.component_id` is the join key back to a nano log source: the config
-- generator names every source `<safe_name(name)>_source`, where `safe_name`
-- maps non-alphanumerics to `_` and lowercases. Attribution is therefore a
-- string comparison, not a lookup table.
--
-- WRITTEN DIRECTLY, NOT VIA A NULL+MV PAIR
-- ----------------------------------------
-- Unlike the OTLP lanes (138/140), there is no derivation to do: Vector's
-- clickhouse sink writes JSON whose keys already match these column names, so
-- the sink's implicit no-column-list INSERT populates the table as-is. Adding a
-- staging table and a materialized view would buy nothing and cost a hop.
--
-- Columns Vector does not emit for a given event simply take their DEFAULT —
-- `skip_unknown_fields` on the sink covers the reverse case (Vector emitting
-- keys we do not model, e.g. per-error-type extras).
--
-- RETENTION
-- ---------
-- 14 days. These are operational diagnostics, not security telemetry: their job
-- is to answer "why is this source failing right now", and a fortnight is well
-- past the point where a stale collector error is still the explanation. The
-- `logs` table's 365-day retention would be actively wrong here — this is
-- high-cardinality churn during an outage and near-empty otherwise.

CREATE TABLE IF NOT EXISTS nanosiem.collector_errors
(
    -- Vector stamps this on every internal log event.
    `timestamp` DateTime64(3) DEFAULT now64(3),

    -- `metadata.level`, flattened by the sink's encoding. WARN or ERROR only —
    -- the transform filters everything else out before it reaches this table.
    `level` LowCardinality(String) DEFAULT '',

    `message` String DEFAULT '',

    -- Vector's stable machine-readable code, e.g. `failed_fetching_sqs_events`.
    -- Present on most but not all internal events, hence the DEFAULT.
    `error_code` LowCardinality(String) DEFAULT '',
    `error_type` LowCardinality(String) DEFAULT '',

    -- `receiving` / `processing` / `sending` — which end of the pipeline broke.
    `stage` LowCardinality(String) DEFAULT '',

    -- The join key: `<safe_name>_source` for sources we generate.
    `component_id` LowCardinality(String) DEFAULT '',
    `component_kind` LowCardinality(String) DEFAULT '',
    -- The Vector driver — `aws_s3`, `kafka`, `gcp_pubsub`, … Useful for
    -- answering "is this transport broken everywhere or just here".
    `component_type` LowCardinality(String) DEFAULT '',

    -- Which collector instance reported it. Matters once more than one Vector
    -- writes to the same cluster.
    `host` String DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
-- component_id leads: every read path is "recent errors for THIS source", so
-- the primary key prefix is the filter and the partition prune handles time.
ORDER BY (component_id, timestamp)
TTL toDateTime(timestamp) + toIntervalDay(14)
SETTINGS index_granularity = 8192;
