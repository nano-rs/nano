-- NAN-1572: register OTLP (OpenTelemetry) as a first-class system-level
-- ingestion listener, paralleling the HTTP/Vector seeds in 047 and the Splunk
-- HEC single-instance backstop in 184.
--
-- The OTLP OOTB Vector listener (config/vector/03-otlp-source.toml, gRPC :4317
-- + HTTP :4318, NAN-1528) is platform-managed and always running. A user `otlp`
-- source config is a routing profile over that shared listener, not a new
-- socket — `otlp_logs_prep` tags `.source_type` and already feeds
-- `source_router`. `SourceConfigService::system_intermediary_source` maps
-- `otlp` → `otlp_logs_prep`; `is_single_instance_driver` rejects a second row;
-- and `base_router_inputs`' `otlp_logs_prep_covered` flag suppresses the direct
-- base input when a meaningful otlp route is on disk (no double-write).

-- Step 1: seed the OOTB OTLP source config (system-level, always enabled —
-- the listener needs no per-tenant credentials, unlike HEC). Mirrors the
-- HTTP/Vector seeds (047 id ...001/...002). Next id in the system block.
INSERT INTO source_configurations (
    id, name, description, config_type, connection_config, enabled, deployed, deployed_at
) VALUES (
    '30000000-0000-0000-0000-000000000007',
    'OpenTelemetry (OTLP)',
    'Receives OpenTelemetry logs via OTLP (gRPC :4317, HTTP :4318). System-level source always enabled. Logs route by the .source_type tag set by otlp_logs_prep.',
    'otlp',
    '{}'::jsonb,
    true,
    true,
    NOW()
) ON CONFLICT (name) DO NOTHING;

-- Step 2: single-instance backstop (mirrors 184 for splunk_hec). The OOTB
-- :4317/:4318 listener is shared; two otlp configs would emit colliding
-- `otlp_route` transforms over `otlp_logs_prep`. Application-level enforcement
-- lives in `SourceConfigService::is_single_instance_driver`; this partial
-- unique index is the DB-level backstop against a check-then-act race.
CREATE UNIQUE INDEX IF NOT EXISTS source_configurations_single_otlp
    ON source_configurations (config_type)
    WHERE config_type = 'otlp';

COMMENT ON INDEX source_configurations_single_otlp IS
    'NAN-1572: enforces that only one otlp source configuration may exist. The OOTB listener (:4317/:4318) is shared; a user config is a routing profile over it. See SourceConfigService::is_single_instance_driver.';

-- Step 3: default passthrough routing rule (mirrors the HTTP/Vector/HEC default
-- in 047/185). `otlp_logs_prep` sets `.source_type` (today `otlp_log`; per-
-- service source_types arrive with the OTLP-log envelope mapping, NAN-1556), so
-- a default-passthrough keeps it and lets OTLP-log parsers' match_values claim
-- events directly off `otlp_logs_prep`. Target is 'unknown' to satisfy the
-- [A-Za-z0-9_-] validator (181/858); the generator overrides it to the inbound
-- source_type for system-level configs. A default-only config writes no route
-- file (has_meaningful_routing_rules=false), so `otlp_logs_prep` stays a direct
-- base input — no suppression, no double-write.
INSERT INTO routing_rules (source_configuration_id, priority, match_field, match_type, match_value, target_source_type)
SELECT '30000000-0000-0000-0000-000000000007'::uuid, 1000, 'source_type', 'default', NULL, 'unknown'
WHERE EXISTS (
    SELECT 1 FROM source_configurations
    WHERE id = '30000000-0000-0000-0000-000000000007'
)
ON CONFLICT DO NOTHING;
