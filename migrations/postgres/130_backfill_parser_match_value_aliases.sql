-- Backfill parser match_values with all known aliases.
--
-- Hardcoded source_type alias normalization has been removed from the Vector
-- pipeline (00-base.toml and 01-vector-source.toml). The dynamic router now
-- relies entirely on each parser's match_values to route events. This migration
-- ensures every parser's match_values includes the aliases that were previously
-- normalized by the hardcoded VRL blocks.
--
-- Each UPDATE uses array_cat + SELECT DISTINCT to merge without duplicates.

-- Apache: apache_access, apache, httpd
UPDATE log_sources
SET match_values = (
    SELECT ARRAY(SELECT DISTINCT unnest(
        array_cat(match_values, ARRAY['apache_access', 'apache', 'httpd'])
    ))
)
WHERE 'apache_access' = ANY(match_values)
   OR 'apache' = ANY(match_values)
   OR 'httpd' = ANY(match_values)
   OR name ILIKE '%apache%'
   OR name ILIKE '%httpd%';

-- Windows Event: windows_event, winlog, windows, winevt
UPDATE log_sources
SET match_values = (
    SELECT ARRAY(SELECT DISTINCT unnest(
        array_cat(match_values, ARRAY['windows_event', 'winlog', 'windows', 'winevt'])
    ))
)
WHERE 'windows_event' = ANY(match_values)
   OR name ILIKE '%windows%event%';

-- AWS CloudTrail: aws_cloudtrail, cloudtrail, aws_ct
UPDATE log_sources
SET match_values = (
    SELECT ARRAY(SELECT DISTINCT unnest(
        array_cat(match_values, ARRAY['aws_cloudtrail', 'cloudtrail', 'aws_ct'])
    ))
)
WHERE 'aws_cloudtrail' = ANY(match_values)
   OR name ILIKE '%cloudtrail%';

-- Syslog: syslog, rsyslog, syslog-ng
UPDATE log_sources
SET match_values = (
    SELECT ARRAY(SELECT DISTINCT unnest(
        array_cat(match_values, ARRAY['syslog', 'rsyslog', 'syslog-ng'])
    ))
)
WHERE 'syslog' = ANY(match_values)
   OR name ILIKE '%syslog%';

-- Palo Alto: palo_alto, pan, panos
UPDATE log_sources
SET match_values = (
    SELECT ARRAY(SELECT DISTINCT unnest(
        array_cat(match_values, ARRAY['palo_alto', 'pan', 'panos'])
    ))
)
WHERE 'palo_alto' = ANY(match_values)
   OR name ILIKE '%palo%alto%';

-- Cisco ASA: cisco_asa, asa, cisco_firewall
UPDATE log_sources
SET match_values = (
    SELECT ARRAY(SELECT DISTINCT unnest(
        array_cat(match_values, ARRAY['cisco_asa', 'asa', 'cisco_firewall'])
    ))
)
WHERE 'cisco_asa' = ANY(match_values)
   OR name ILIKE '%cisco%asa%';

-- Fortinet: fortinet, fortigate, fgt
UPDATE log_sources
SET match_values = (
    SELECT ARRAY(SELECT DISTINCT unnest(
        array_cat(match_values, ARRAY['fortinet', 'fortigate', 'fgt'])
    ))
)
WHERE 'fortinet' = ANY(match_values)
   OR name ILIKE '%fortinet%'
   OR name ILIKE '%fortigate%';
