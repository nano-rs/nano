-- Shadow Investigation Cost Attribution (NAN-1491)
--
-- Phase 3 of agent-runtime hardening: surface the provider token usage the AI
-- gateway already parses (prompt/completion/cached/cache-creation) out to a
-- per-investigation cost summary. One row per investigation; per-agent token +
-- cost breakdown lives in the `per_agent` jsonb so the cost concern stays
-- decoupled from the shadow_investigations lifecycle row.
--
-- Cost is an ESTIMATE: it joins captured model ids against available_models
-- pricing at full input/output rate. Cached tokens have no discounted price
-- column today, so cache-heavy agents are over-estimated; missing pricing
-- contributes 0 cost while token counts are still persisted. No new status
-- value is introduced, so the shadow_investigations status CHECK is untouched.

CREATE TABLE IF NOT EXISTS shadow_investigation_costs (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  investigation_id UUID NOT NULL REFERENCES shadow_investigations(id) ON DELETE CASCADE,
  total_prompt_tokens BIGINT NOT NULL DEFAULT 0,
  total_completion_tokens BIGINT NOT NULL DEFAULT 0,
  total_cached_tokens BIGINT NOT NULL DEFAULT 0,
  total_cache_creation_tokens BIGINT NOT NULL DEFAULT 0,
  estimated_cost_usd NUMERIC(12,6),
  per_agent JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One cost row per investigation. The unique index is the upsert target so a
-- resume / follow-up re-run overwrites the prior totals rather than appending.
CREATE UNIQUE INDEX IF NOT EXISTS idx_shadow_inv_costs_inv
  ON shadow_investigation_costs(investigation_id);
