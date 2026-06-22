-- NAN-1519: per-call AI usage ledger.
--
-- Numbered 208, not 204 (NAN-1520): versions 204–207 are burned. They shipped
-- in v0.1.625–627 as core shadow-investigation/retriage/bedrock migrations
-- (#2327), then #2342 moved shadow+bedrock to the enterprise overlay
-- (9000016/9000017) and deleted the core files — but left the applied
-- `_sqlx_migrations` rows behind. Reusing 204 would abort with "migration 204
-- was previously applied but has been modified" on any DB that rolled through
-- those releases. 208 clears the whole burned range; the 204–207 gap is
-- intentional (orphan rows stay tolerated by `ignore_missing`).
--
-- `ai_request_counts` (migration 138) is a single cumulative row per month used
-- as the atomic rate-limit guard — it answers "how many billable credits this
-- month" but nothing about WHAT consumed them. This table is the observability
-- counterpart: one row per successful LLM call, fed from the single universal
-- chokepoint `log_usage()` in nanosiem-enterprise's ai_gateway (every provider
-- response funnels through it). It carries the logical agent, model/provider,
-- and the REAL token counts already in hand at that point, so the Usage surface
-- can show per-agent breakdowns, a daily trend, and a recent-call log.
--
-- Billing vs. observability are deliberately decoupled: a single user request
-- (one credit charge via ai_request_counts) may make several internal LLM calls
-- (several rows here). The headline credits-used figure stays sourced from
-- `ai_request_counts`; this ledger powers the detail views. The per-row
-- `credits` column is a per-call cost-equivalent (ai_request_cost(model)),
-- useful for relative attribution, NOT a billing total.

-- NAN-1524: self-heal the backfill source. `ai_request_counts` (migration 138)
-- was dropped from the open-init snapshot during the open-core split, so on a
-- fresh DB carrying that stale snapshot 138 is skipped (<= baseline 175) and the
-- table is absent — making the `INSERT ... FROM ai_request_counts` below fail
-- with 42P01. Idempotent; a no-op wherever 138 / the fixed snapshot already
-- created it. Matches migration 138's definition exactly.
CREATE TABLE IF NOT EXISTS public.ai_request_counts (
    id SERIAL PRIMARY KEY,
    month TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(month)
);

CREATE TABLE IF NOT EXISTS public.ai_usage_events (
    id bigserial PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    -- Billing-period bucket as 'YYYY-MM' (UTC), matching ai_request_counts.month
    -- so the two tables join/compare cleanly.
    month text NOT NULL,
    -- Logical agent that made the call (e.g. 'detection', 'shadow_hunting',
    -- 'enrichment_code_gen'). 'unknown' when no agent scope was active.
    agent text NOT NULL DEFAULT 'unknown',
    model_id text NOT NULL DEFAULT '',
    provider text NOT NULL DEFAULT '',
    -- Real token counts as reported by the provider (see ai_gateway CapturedUsage).
    prompt_tokens bigint NOT NULL DEFAULT 0,
    completion_tokens bigint NOT NULL DEFAULT 0,
    -- Cached input tokens (OpenAI cached_tokens + Anthropic cache_read).
    cached_tokens bigint NOT NULL DEFAULT 0,
    -- Anthropic cache-write tokens (cache_creation_input_tokens).
    cache_creation_tokens bigint NOT NULL DEFAULT 0,
    -- Per-call credit-equivalent (ai_request_cost(model_id): lite=2, full=10).
    -- Relative-attribution only; not a billable total (see table comment).
    credits integer NOT NULL DEFAULT 0
);

COMMENT ON TABLE public.ai_usage_events IS
  'NAN-1519: one row per successful LLM call (fed from ai_gateway log_usage). Observability ledger for per-agent / daily / recent-call AI usage. Billing total stays in ai_request_counts.';

-- Time-bounded reads for the daily trend and recent-call log.
CREATE INDEX IF NOT EXISTS idx_ai_usage_events_occurred_at
    ON public.ai_usage_events USING btree (occurred_at DESC);

-- Per-agent rollups within a month.
CREATE INDEX IF NOT EXISTS idx_ai_usage_events_month_agent
    ON public.ai_usage_events USING btree (month, agent);

-- Seed a single backfill row so the detail views don't understate credits
-- already consumed this month before per-call tracking existed. Labelled
-- distinctly; carries credits only (no token detail is recoverable). Skipped
-- when this month has no prior usage.
INSERT INTO public.ai_usage_events (occurred_at, month, agent, model_id, provider, credits)
SELECT now(), c.month, 'prior_to_tracking', '', '', c.request_count
FROM public.ai_request_counts c
WHERE c.month = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM')
  AND c.request_count > 0;
