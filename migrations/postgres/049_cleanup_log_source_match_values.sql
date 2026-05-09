-- Clean up log_sources match_values to use single, canonical source_type values
-- The old seed data had multiple aliases like {sysmon, windows_sysmon} but
-- the router only matches on exact values like 'sysmon'

-- Update existing log sources to use clean, single match_values
UPDATE log_sources SET match_values = ARRAY['apache']
WHERE name = 'Apache' OR 'apache_access' = ANY(match_values) OR 'apache_error' = ANY(match_values);

UPDATE log_sources SET match_values = ARRAY['sysmon']
WHERE name = 'Sysmon' OR 'windows_sysmon' = ANY(match_values);

UPDATE log_sources SET match_values = ARRAY['squid_proxy']
WHERE name = 'Squid Proxy' OR 'squid' = ANY(match_values);

UPDATE log_sources SET match_values = ARRAY['json_generic']
WHERE name = 'Json Generic' OR 'json' = ANY(match_values);

-- Fix any f5_waf entries that might have wrong match_values
UPDATE log_sources SET match_values = ARRAY['f5_waf']
WHERE name = 'f5_waf' OR 'waf' = ANY(match_values);

-- Clean up alias routing rules (keep only canonical source_type values)
DELETE FROM routing_rules WHERE match_value IN ('apache_access', 'apache_error', 'json', 'squid', 'windows_sysmon');
