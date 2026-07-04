-- =============================================================================
-- 154: finish the ingest private-IP exclusion fix — OCSF prevalence_dest_ip and
--      UDM prevalence_min still carried the incomplete startsWith set (NAN-1666)
-- =============================================================================
--
-- NAN-1661/151 fixed the exclusion set on UDM logs.prevalence_dest_ip to the full
-- match() regex, but two sibling ingest-stamp expressions were left on the OLD
-- startsWith set:
--     startsWith(ip,'10.') OR startsWith(ip,'172.16.')
--     OR startsWith(ip,'192.168.') OR startsWith(ip,'127.')
-- which MISSES:
--   * 172.17.0.0 – 172.31.255.255  (only the '172.16.' /16 was caught, not the
--     full 172.16.0.0/12 — where Docker's default bridge networks live)
--   * 169.254.0.0/16  (link-local)
-- Those addresses fell through to the ip_prevalence_dict lookup (source holds
-- only public IPs, WHERE is_private = 0), so a private dest IP got a real
-- prevalence stamp / polluted rare-artifact hunts instead of the 65535
-- "N/A — private" sentinel. This replaces both with the SAME match() regex the
-- ip_prevalence agg/summary MVs use for is_private classification, matching UDM
-- logs.prevalence_dest_ip exactly.
--
-- The two remaining sites:
--   1. OCSF ocsf_logs.prevalence_dest_ip (MATERIALIZED). OCSF prevalence_min is a
--      least() over the four prevalence_* columns, so it inherits this fix — no
--      separate statement. Marked skip-if-unknown-table (ocsf_logs only exists on
--      NANO_SCHEMA_PROFILE=ocsf).
--   2. UDM logs.prevalence_min (DEFAULT) — its inlined dest_ip branch (UDM's
--      prevalence_dest_ip MATERIALIZED column was already fixed by 151; the
--      prevalence_min DEFAULT inlines its own copy of the branch and was missed).
--
-- Not-found default is toUInt16(1) "genuinely new" (per NAN-1662/153), not the
-- pre-153 9999 — this migration only touches the exclusion regex, nothing else.
--
-- ALTER … MODIFY COLUMN on a MATERIALIZED/DEFAULT expression is METADATA-ONLY: it
-- changes FUTURE inserts and does NOT rewrite existing parts (verified). No
-- MATERIALIZE/backfill — that would be a multi-TB part rewrite in the boot-gating
-- migrator (forbidden, NAN-1398/1404). Go-forward inserts are stamped correctly.
--
-- Keep in lockstep with clickhouse/ocsf/init.sql and clickhouse/init.sql (fresh
-- bootstraps).
-- =============================================================================

-- 1. OCSF ocsf_logs.prevalence_dest_ip — full match() exclusion set.
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    MODIFY COLUMN `prevalence_dest_ip` UInt16 MATERIALIZED if(`dst_endpoint.ip` != '' AND NOT (match(`dst_endpoint.ip`, '^10\\.') OR match(`dst_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') OR match(`dst_endpoint.ip`, '^192\\.168\\.') OR match(`dst_endpoint.ip`, '^127\\.') OR match(`dst_endpoint.ip`, '^169\\.254\\.')), dictGetOrDefault('nanosiem.ip_prevalence_dict', 'host_count', `dst_endpoint.ip`, toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4);

-- 2. UDM logs.prevalence_min — full match() exclusion set on the dest_ip branch
--    (other three branches unchanged; restated because MODIFY COLUMN replaces the
--    whole DEFAULT expression).
ALTER TABLE nanosiem.logs
    MODIFY COLUMN `prevalence_min` UInt16 DEFAULT least(
        if(file_hash != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', lower(file_hash), toUInt16(1)), toUInt16(9999)),
        if(process_hash != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', lower(process_hash), toUInt16(1)), toUInt16(9999)),
        if(dest_host != '' AND NOT match(dest_host, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'), dictGetOrDefault('nanosiem.domain_prevalence_dict', 'host_count', lower(dest_host), toUInt16(1)), toUInt16(9999)),
        if(dest_ip != '' AND NOT (match(dest_ip, '^10\\.') OR match(dest_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') OR match(dest_ip, '^192\\.168\\.') OR match(dest_ip, '^127\\.') OR match(dest_ip, '^169\\.254\\.')), dictGetOrDefault('nanosiem.ip_prevalence_dict', 'host_count', dest_ip, toUInt16(1)), toUInt16(9999))
    ) CODEC(T64, LZ4);
