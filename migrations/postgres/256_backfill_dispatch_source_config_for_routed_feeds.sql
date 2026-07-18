-- NAN-1906: backfill dispatch_source_config_id for existing routed feeds.
--
-- Feeds onboarded through the AddFeed wizard were written with
-- source_type='routed' and dispatch_source_config_id=NULL. The Log Sources
-- list LEFT JOINs source_configurations on dispatch_source_config_id (NAN-1084);
-- with no link it found no config_type and fell back to source_type, so every
-- pull transport (GCP Pub/Sub, Kafka, AWS S3, Splunk HEC) rendered as "HTTP".
-- The code fix records the id on NEW feeds; this repairs EXISTING ones.
--
-- The link is recoverable: AddFeed created a routing rule on the picked source
-- config with target_source_type = <feedId>, and the log source carries that
-- same feedId in match_values. So: log_sources.match_values ∋ a value equal to
-- routing_rules.target_source_type → routing_rules.source_configuration_id.
--
-- Safety:
--   * Only UNAMBIGUOUS feeds (exactly one source config per target_source_type)
--     are relinked; ambiguous feedIds are left NULL and keep falling back to
--     source_type (unchanged "HTTP") rather than guessing.
--   * routing_rules.source_configuration_id FKs source_configurations
--     ON DELETE CASCADE, so every candidate config is guaranteed to exist — the
--     backfill can never create a dangling dispatch_source_config_id.
--   * Idempotent: only rows still NULL are touched, so re-running is a no-op;
--     fresh installs with no affected feeds update zero rows.

UPDATE log_sources ls
SET dispatch_source_config_id = m.source_configuration_id,
    updated_at = NOW()
FROM (
    SELECT rr.target_source_type,
           -- PG has no MIN(uuid); config_count=1 below guarantees a single
           -- distinct id, so take element [1] of the distinct array.
           (array_agg(DISTINCT rr.source_configuration_id))[1] AS source_configuration_id,
           COUNT(DISTINCT rr.source_configuration_id) AS config_count
    FROM routing_rules rr
    GROUP BY rr.target_source_type
) m
WHERE ls.dispatch_source_config_id IS NULL
  AND ls.source_type = 'routed'
  AND m.config_count = 1
  AND m.target_source_type = ANY(ls.match_values);
