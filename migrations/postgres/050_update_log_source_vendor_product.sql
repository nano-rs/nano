-- Update log_sources with correct vendor, product, and category values
-- These should match the seed data and flow through to ClickHouse

-- Apache
UPDATE log_sources SET
    vendor = 'Apache Software Foundation',
    product = 'Apache HTTP Server',
    category = 'Web Server'
WHERE name = 'Apache' OR 'apache' = ANY(match_values);

-- Sysmon
UPDATE log_sources SET
    vendor = 'Microsoft',
    product = 'Sysmon',
    category = 'Endpoint'
WHERE name = 'Sysmon' OR 'sysmon' = ANY(match_values);

-- Squid Proxy
UPDATE log_sources SET
    vendor = 'Squid Project',
    product = 'Squid Proxy',
    category = 'Network'
WHERE name = 'Squid Proxy' OR 'squid_proxy' = ANY(match_values);

-- Json Generic
UPDATE log_sources SET
    vendor = 'NanoSIEM',
    product = 'JSON Parser',
    category = 'Generic'
WHERE name = 'Json Generic' OR 'json_generic' = ANY(match_values);

-- F5 WAF
UPDATE log_sources SET
    vendor = 'F5',
    product = 'BIG-IP ASM',
    category = 'Security'
WHERE name ILIKE '%f5%' OR 'f5_waf' = ANY(match_values);
