-- Fix Apache parser match_values to use 'apache_access' instead of 'apache'.
--
-- Migration 049 normalized match_values to ['apache'], but log shippers
-- (log-blaster, generate-apache-logs.py) and source config routing rules
-- all use 'apache_access' as the source_type value. The generated Vector
-- router checks match_values to build route conditions, so these must
-- match what actually arrives in the X-Source-Type header / JSON body.
--
-- The old 00-base.toml had a hardcoded alias (apache_access → apache) that
-- papered over this mismatch locally, but the K8s deployment doesn't use
-- those aliases — it relies entirely on the dynamic router.

UPDATE log_sources
SET match_values = ARRAY['apache_access']
WHERE 'apache' = ANY(match_values)
  AND (name ILIKE '%apache%' OR name ILIKE '%httpd%');
