-- NAN-1100: drop the legacy well-known seeded routing rules that were
-- re-seeded onto the OOTB HTTP Ingestion source configuration by migration
-- 177.
--
-- Background: migration 047 originally seeded the HTTP Ingestion source
-- config (id 30000000-0000-0000-0000-000000000001) with 9 normalization
-- rules (apache/json/squid/sysmon variants -> legacy parser names). These
-- *rewrite* source_type — e.g. an event arriving as `apache_access` is
-- rewritten to `apache`. Migration 115 deleted those rules ("new
-- deployments should start clean — users configure their own source types
-- via parser repositories or the UI"), and migration 130 moved all aliasing
-- into each parser's `match_values` so the dynamic router no longer rewrites
-- source_type at all.
--
-- Migration 177 (NAN-791) rebuilt the open-tier baseline for fresh deploys
-- and copied 047's routing-rule block verbatim, silently undoing 115. The
-- effect: log-blaster / shippers sending `source_type=apache_access` have it
-- rewritten to `apache` (and `windows_sysmon` -> `sysmon`), and the correct
-- parser-claimed identity route (`apache_access -> apache_access`) is
-- shadowed as dead `else-if` because the re-seeded rule has a lower priority
-- number and wins the generated if/else-if chain.
--
-- This is the HTTP-Ingestion analogue of migration 186 (NAN-920), which did
-- the same cleanup for the Splunk HEC config after its own 185 re-seed. We
-- mirror 186's approach exactly: delete only rows whose
-- `(priority, match_field, match_type, match_value, target_source_type)`
-- tuple matches the 177 seed verbatim. Any rule the user has edited
-- (changed target, reordered, added) does not match the tuple and is
-- preserved. Parser-claimed identity routes (target == match_value, distinct
-- priorities) never match these rewriting tuples and are preserved.
--
-- We do NOT modify migration 177 itself — editing an applied migration
-- breaks sqlx checksums on every existing tenant. This forward cleanup is
-- the established pattern (047 -> 115, 185 -> 186). On a fresh deploy 177
-- seeds the 9 rows and this migration removes them; on existing tenants it
-- removes the re-seeded rows in place. Idempotent: a DELETE that matches no
-- rows (e.g. a tenant that never re-seeded, or one already cleaned) is a
-- no-op.
--
-- The default rule (priority 1000, target='unknown') is intentionally NOT
-- touched — the generator emits passthrough for system-level configs, so the
-- default is the load-bearing rule that lets unmatched events flow through to
-- parser matching.

DELETE FROM routing_rules
WHERE source_configuration_id = '30000000-0000-0000-0000-000000000001'::uuid
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
