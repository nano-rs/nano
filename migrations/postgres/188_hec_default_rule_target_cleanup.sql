-- NAN-925: clean up the stale `target_source_type` value on the HEC
-- source config's default routing rule for tenants who imported a HEC
-- parser pre-NAN-918.
--
-- Background: before NAN-918 shipped, `is_pull_source_source_type_match`
-- treated `splunk_hec` as a pull source. The parser-repository import
-- flow's auto-created rule (`match_field='source_type'`,
-- `match_type='exact'`, `match_value=<parser_name>`,
-- `target_source_type=<parser_name>`) had its match_type silently
-- coerced to `default` by `coerce_pull_source_match_type`. The result
-- was a default rule at priority 1000 with `target_source_type` set to
-- the first imported parser's name (typically `apache_access`).
--
-- Runtime is unaffected since NAN-918: the generator
-- (`SourceConfigService::generate_routing_transform`) overrides any
-- default rule's `target_source_type` to passthrough for system-level
-- configs (`routing_default_passthrough = is_system_level`). So the
-- stored value never reaches the deployed VRL — events flow through
-- correctly.
--
-- But the UI reads the raw DB value, so users see
-- "FALLBACK → apache_access" on the HEC source config detail page,
-- which is confusing. This migration normalises that stored value to
-- `unknown` to match the seed (migration 185) and the canonical
-- passthrough-sentinel convention.
--
-- Migration 186 intentionally only deleted the specific seeded rules
-- (preserved user-edited defaults to avoid data loss). This migration
-- only touches the default rule on the OOTB HEC config (id
-- `30000000-0000-0000-0000-000000000006`), not any other config's
-- defaults. Idempotent — `target_source_type <> 'unknown'` skips rows
-- that are already in the canonical state.

UPDATE routing_rules
SET target_source_type = 'unknown'
WHERE source_configuration_id = '30000000-0000-0000-0000-000000000006'::uuid
  AND match_type = 'default'
  AND target_source_type <> 'unknown';
