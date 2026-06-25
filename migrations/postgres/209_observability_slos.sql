-- NAN-1536: Service-level objectives (SLOs) for the Observability console.
--
-- SLO *definitions* are tenant metadata and live in PostgreSQL. The
-- *attainment* (current SLI, error budget remaining, burn rate, status) is
-- NOT stored — it is computed on read from `otel_spans` over the SLO's
-- rolling `window_days` window (see nanosiem-core `slo_compute_sql` /
-- `observability_slo_compute`). Keeping only the definition here avoids a
-- background job and keeps the number always consistent with the spans.
--
-- Two SLI kinds:
--   * availability — fraction of non-ERROR spans for the service.
--   * latency      — fraction of spans under `latency_threshold_ms`.
-- `target` is the objective as a fraction in (0,1] (e.g. 0.995 = 99.5%).

CREATE TABLE IF NOT EXISTS observability_slos (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Human label for the SLO card (e.g. "Checkout availability").
    name TEXT NOT NULL,
    -- The OTLP `service.name` the SLO is measured against.
    service TEXT NOT NULL,
    -- 'availability' | 'latency'. Validated at the API layer; CHECK guards the DB.
    sli_kind TEXT NOT NULL CHECK (sli_kind IN ('availability', 'latency')),
    -- Objective as a fraction in (0,1], e.g. 0.995.
    target DOUBLE PRECISION NOT NULL CHECK (target > 0 AND target <= 1),
    -- Rolling evaluation window in days (1..=90).
    window_days INTEGER NOT NULL CHECK (window_days >= 1 AND window_days <= 90),
    -- Required for sli_kind='latency': the per-span duration threshold (ms)
    -- under which a span counts as "good". NULL for availability SLOs.
    latency_threshold_ms DOUBLE PRECISION,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- A latency SLO must carry a threshold; an availability SLO must not.
    CONSTRAINT observability_slos_latency_threshold_consistency CHECK (
        (sli_kind = 'latency' AND latency_threshold_ms IS NOT NULL AND latency_threshold_ms > 0)
        OR (sli_kind = 'availability' AND latency_threshold_ms IS NULL)
    )
);

-- Console lists SLOs grouped/ordered by service.
CREATE INDEX IF NOT EXISTS idx_observability_slos_service
    ON observability_slos (service, created_at DESC);
