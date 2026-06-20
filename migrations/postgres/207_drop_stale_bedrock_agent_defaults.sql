-- NAN-1501: Drop the stale bedrock hardcoded defaults for first-party agents.
--
-- `ai_pipe`, `shadow_hunting`, and `shadow_narrative` were seeded pinned to
-- `bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0` in already-applied
-- migrations (085_shadow_agent_configs.sql, 098_ai_pipe_agent.sql, and the
-- enterprise baseline 9000003_seed_enterprise_baseline.sql). The bedrock
-- provider, however, is seeded `enabled = false` (040_litellm_provider_config),
-- so on any tenant that never configured AWS Bedrock these three agents resolve
-- to `ProviderNotFound("bedrock")`. Because MelodService::from_registry builds a
-- client for every required agent at boot, one unresolvable provider aborts the
-- entire service — taking down all of meloD/PIVT, not just the bedrock agents.
--
-- We can't edit 085/098/9000003 (applied; sqlx checksums would break upgrades),
-- so this forward migration repoints the three agents to the anthropic-native id
-- for the SAME model (Claude Sonnet 4.5), matching their capable-tier siblings
-- (enrichment_codegen, udm_validation) which already use anthropic/claude-sonnet-4-5.
-- Token budgets / temperature / timeout are left untouched; the model catalog
-- sync will retune them per the enabled provider's tier on its next tick.
--
-- Guards:
--   * `model_id LIKE 'bedrock/%'` — only touch rows still on the stale default.
--   * `source != 'custom'` — never clobber a deliberate user choice (e.g. a
--     tenant that rolled custom GLM models onto these agents). The companion
--     code change (NAN-1501) lets the catalog sync manage first-party agents
--     even when source='custom', but a one-shot data migration must not.
--   * agent_id allow-list — scope strictly to the three known stale seeds.
--
-- Idempotent: a second run finds no `bedrock/%` rows for these agents and is a
-- no-op. No-op on tenants that already migrated off bedrock.

UPDATE agent_model_config
   SET model_id = 'anthropic/claude-sonnet-4-5',
       source = 'upstream',
       updated_at = NOW()
 WHERE model_id LIKE 'bedrock/%'
   AND source != 'custom'
   AND agent_id IN ('ai_pipe', 'shadow_hunting', 'shadow_narrative');
