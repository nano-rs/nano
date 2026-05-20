-- NAN-918: seed the OOTB Splunk HEC source configuration with routing rules
-- paralleling the HTTP seed in 047, so HEC-imported parsers "just work" the
-- same way HTTP-imported parsers do.
--
-- HTTP's pattern (047 lines 180-200):
--   - Specific rules matching well-known source_type values → parser targets
--   - A default rule with target_source_type='unknown' which the routing
--     transform generator interprets as passthrough for system-level configs
--     (see SourceConfigService::generate_routing_transform).
--
-- HEC was previously seeded with an empty rules list (047 lines 249-259),
-- which left users with no auto-routing for the well-known sourcetypes and
-- no default fallback. After NAN-883 reclassified HEC as a push transport
-- alongside HTTP/Vector, the asymmetry became a real UX gap.
--
-- match_field is 'source_type' (not 'sourcetype'): hec_normalize
-- (config/vector/02-hec-source.toml) lowercases the inbound .sourcetype
-- into .source_type before this routing transform runs, so matching on
-- .source_type gives case-insensitive behavior matching what HTTP does.
-- The companion code change (NAN-918) makes splunk_hec participate in the
-- system-level passthrough path, so .source_type rules are no longer
-- skipped by `is_pull_source_source_type_match`.

INSERT INTO routing_rules (source_configuration_id, priority, match_field, match_type, match_value, target_source_type)
SELECT '30000000-0000-0000-0000-000000000006'::uuid, priority, 'source_type', match_type, match_value, target_source_type
FROM (VALUES
    -- Apache
    (10,   'exact',   'apache',           'apache'),
    (11,   'exact',   'apache_access',    'apache'),
    (12,   'exact',   'apache_error',     'apache'),
    -- JSON generic
    (20,   'exact',   'json',             'json_generic'),
    (21,   'exact',   'json_generic',     'json_generic'),
    -- Squid proxy
    (30,   'exact',   'squid',            'squid_proxy'),
    (31,   'exact',   'squid_proxy',      'squid_proxy'),
    -- Sysmon
    (40,   'exact',   'sysmon',           'sysmon'),
    (41,   'exact',   'windows_sysmon',   'sysmon'),
    -- Default passthrough: generator overrides this target to ${source_type}
    -- when the config is system-level (post-NAN-918 includes splunk_hec).
    -- We store 'unknown' to satisfy the [A-Za-z0-9_-] target validator
    -- (NAN-858 / migration 181); the generator never reads the stored value
    -- for system-level defaults.
    (1000, 'default', NULL,               'unknown')
) AS rules(priority, match_type, match_value, target_source_type)
-- Only seed if the OOTB HEC config exists (it's created in migration 047,
-- but defensive in case a tenant removed it).
WHERE EXISTS (
    SELECT 1 FROM source_configurations
    WHERE id = '30000000-0000-0000-0000-000000000006'
)
-- Idempotent: skip if (config_id, priority) collides — the routing_rules
-- table has UNIQUE(source_configuration_id, priority) per 047.
ON CONFLICT DO NOTHING;
