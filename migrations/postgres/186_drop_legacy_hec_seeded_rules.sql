-- NAN-920: drop the legacy well-known seeded routing rules from the OOTB
-- Splunk HEC source configuration.
--
-- Migration 185 (NAN-918) seeded the HEC source config with 9 specific
-- rules mirroring HTTP's seed in 047 (apache/json/squid/sysmon variants
-- → legacy parser names). The legacy target_source_type values
-- (`apache`, `json_generic`, `squid_proxy`, `sysmon`) don't match the
-- canonical names used by modern open-source parser repositories
-- (`apache_http_server`, `microsoft_sysmon`, `conduit_mitm_proxy`, …),
-- so they render as orphan-target warnings in the routing-rule UI
-- (`SourceConfigurationDetail.tsx:1582-1583` — `hasParser` check fails
-- when neither `source_type` nor any `match_values` entry on an existing
-- log source equals the rule's `target_source_type`).
--
-- The companion code change (NAN-920 — `ParserRepositoryService::resolve_match_values`)
-- now unions the YAML's `match_values` into the imported log source so
-- the legacy aliases are tracked alongside the canonical name. New
-- imports going forward will satisfy the `hasParser` check for any
-- specific rule the user later adds.
--
-- We delete only rules whose `(priority, match_field, match_type,
-- match_value, target_source_type)` tuple matches the original seed
-- verbatim. Any rule the user has already edited (changed
-- target_source_type, added new rules, or reordered) is preserved.
--
-- The default rule (priority 1000, target='unknown', generator emits
-- passthrough for system-level configs) is intentionally NOT touched —
-- it's the load-bearing rule that makes HEC events without an explicit
-- routing match flow through to parser matching.

DELETE FROM routing_rules
WHERE source_configuration_id = '30000000-0000-0000-0000-000000000006'::uuid
  AND match_field = 'source_type'
  AND match_type = 'exact'
  AND (
        (priority = 10  AND match_value = 'apache'          AND target_source_type = 'apache')
     OR (priority = 11  AND match_value = 'apache_access'   AND target_source_type = 'apache')
     OR (priority = 12  AND match_value = 'apache_error'    AND target_source_type = 'apache')
     OR (priority = 20  AND match_value = 'json'            AND target_source_type = 'json_generic')
     OR (priority = 21  AND match_value = 'json_generic'    AND target_source_type = 'json_generic')
     OR (priority = 30  AND match_value = 'squid'           AND target_source_type = 'squid_proxy')
     OR (priority = 31  AND match_value = 'squid_proxy'     AND target_source_type = 'squid_proxy')
     OR (priority = 40  AND match_value = 'sysmon'          AND target_source_type = 'sysmon')
     OR (priority = 41  AND match_value = 'windows_sysmon'  AND target_source_type = 'sysmon')
  );
