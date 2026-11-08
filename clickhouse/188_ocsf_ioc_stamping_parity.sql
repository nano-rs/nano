-- =============================================================================
-- 188: OCSF ingest-time IOC stamping parity with UDM (NAN-4982)
-- =============================================================================
-- On the OCSF profile (the v2 default) `ocsf_logs_raw_mv` stamped only
-- `enrichments.ioc_{src_ip,dest_ip,domain,hash}_threat_type`, from the
-- marketplace `ioc_enrichment_dict`, and matched hashes only through the
-- SHA-256 pick. Three gaps against the UDM `logs` columns:
--   * IOC lists and user IOC enrichments (`custom_ioc_enrichment_dict`) were
--     never looked up: no `custom_ioc_*` columns existed on `ocsf_logs`,
--   * MD5 / SHA-1 indicators never matched (only `*.hashes.sha256` was read),
--     and URL indicators had no slot at all,
--   * no malware / confidence / tags / source columns, so rules written
--     against `ioc_*_confidence`, `ioc_confidence`, `ioc_tags`, `ioc_source`
--     returned nothing.
--
-- 1. ADD the missing columns (plain columns written by the view, exactly like
--    the existing four, `AFTER` keeps the generated column order so fresh and
--    upgraded tables end identical). ADD COLUMN on a plain column is
--    metadata-only: no mutation, old parts read the default ('' / 0). No
--    backfill: a stamp is the IOC verdict at ingest time, the same as UDM's
--    MATERIALIZED columns, and a table-sized rewrite has no place in a boot
--    migration.
-- 2. Swap in the view body scripts/gen-ocsf-ddl.py now renders. MODIFY QUERY,
--    not DROP + CREATE: `ocsf_logs_raw` is ENGINE = Null, so with the view
--    dropped live ingest would be accepted and lost (same reasoning as 165 /
--    185). SELECT directly, no AS (NAN-1727). Hash slots probe at most 16
--    candidates (the first 16 elements of each hashes[] array, recognized
--    algorithm_id 1/2/3 with the matching hex length), so a huge hashes[]
--    array cannot amplify dictionary probes. URL slots match the canonical
--    URL (see 3). The body is byte-identical to the
--    overlay's (guard: nanosiem-core/tests/ocsf_ioc_stamping_guard.rs).
-- 3. Redefine ioc_enrichment_dict and custom_ioc_enrichment_dict (CREATE OR
--    REPLACE: an atomic swap, same as 148) so a `url` key is the CANONICAL URL
--    (scheme and host lowercased; userinfo, port, path, query and fragment
--    preserved, see
--    url_canon_sql in scripts/gen-ocsf-ddl.py and
--    nanosiem_core::enrichment::ioc::canonical_url). Lowercasing the whole URL
--    made `https://User@bad.example/Dropper/A` match a distinct userinfo or
--    path spelling. Every other
--    key type keeps lower() exactly as 148. The swapped-in dictionaries load
--    lazily on first use. UDM never looks a URL up, so its columns are
--    unaffected. init.sql keeps the 148 bodies (never edited) and fresh
--    installs reach these through this migration like an upgrade.
-- 4. GRANT dictGet on custom_ioc_enrichment_dict to nanosiem_ingest: the view
--    runs under the INSERTING user, and a direct OCSF writer would otherwise
--    fail every insert with ACCESS_DENIED. Users from users.d XML are
--    read-only to SQL, so this soft-fails there and the XML carries the grant,
--    it applies to SQL-created users.
-- 5. GRANT SELECT on the three *_prevalence_source_agg tables to
--    nanosiem_ingest. Migration 170's *_prevalence_source_ocsf_mv write into
--    them and their *_prevalence_source_summary_mv SELECT runs under the
--    inserting user (the NAN-1787 chained-MV class, one level further). Without
--    it every direct OCSF write carrying an IP, hash or domain failed with
--    ACCESS_DENIED, so no direct-written event was stamped at all. Same
--    soft-fail / XML split as 4.
--
-- ocsf_logs and its view are absent on UDM-only deployments and on a fresh
-- OCSF install (the overlay runs AFTER numbered migrations and creates the new
-- shape directly), so every ALTER carries skip-if-unknown-table. On explicit
-- clusters the migrator adds ON CLUSTER, and reconcile_distributed_columns adds
-- the new columns to ocsf_logs_distributed. Idempotent: IF NOT EXISTS columns,
-- a MODIFY QUERY to the same body, an idempotent GRANT.

ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.ioc_src_ip_malware` String CODEC(ZSTD(1)) AFTER `enrichments.ioc_src_ip_threat_type`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.ioc_src_ip_confidence` UInt8 CODEC(T64, ZSTD(1)) AFTER `enrichments.ioc_src_ip_malware`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.ioc_dest_ip_malware` String CODEC(ZSTD(1)) AFTER `enrichments.ioc_dest_ip_threat_type`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.ioc_dest_ip_confidence` UInt8 CODEC(T64, ZSTD(1)) AFTER `enrichments.ioc_dest_ip_malware`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.ioc_domain_malware` String CODEC(ZSTD(1)) AFTER `enrichments.ioc_domain_threat_type`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.ioc_domain_confidence` UInt8 CODEC(T64, ZSTD(1)) AFTER `enrichments.ioc_domain_malware`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.ioc_hash_malware` String CODEC(ZSTD(1)) AFTER `enrichments.ioc_hash_threat_type`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.ioc_hash_confidence` UInt8 CODEC(T64, ZSTD(1)) AFTER `enrichments.ioc_hash_malware`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.ioc_url_threat_type` String CODEC(ZSTD(1)) AFTER `enrichments.ioc_hash_confidence`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.ioc_url_malware` String CODEC(ZSTD(1)) AFTER `enrichments.ioc_url_threat_type`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.ioc_url_confidence` UInt8 CODEC(T64, ZSTD(1)) AFTER `enrichments.ioc_url_malware`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.ioc_confidence` UInt8 CODEC(T64, ZSTD(1)) AFTER `enrichments.ioc_url_confidence`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.ioc_tags` String CODEC(ZSTD(1)) AFTER `enrichments.ioc_confidence`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.ioc_source` String CODEC(ZSTD(1)) AFTER `enrichments.ioc_tags`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.custom_ioc_src_ip_threat_type` String CODEC(ZSTD(1)) AFTER `enrichments.ioc_source`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.custom_ioc_src_ip_malware` String CODEC(ZSTD(1)) AFTER `enrichments.custom_ioc_src_ip_threat_type`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.custom_ioc_src_ip_confidence` UInt8 CODEC(T64, ZSTD(1)) AFTER `enrichments.custom_ioc_src_ip_malware`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.custom_ioc_dest_ip_threat_type` String CODEC(ZSTD(1)) AFTER `enrichments.custom_ioc_src_ip_confidence`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.custom_ioc_dest_ip_malware` String CODEC(ZSTD(1)) AFTER `enrichments.custom_ioc_dest_ip_threat_type`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.custom_ioc_dest_ip_confidence` UInt8 CODEC(T64, ZSTD(1)) AFTER `enrichments.custom_ioc_dest_ip_malware`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.custom_ioc_domain_threat_type` String CODEC(ZSTD(1)) AFTER `enrichments.custom_ioc_dest_ip_confidence`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.custom_ioc_domain_malware` String CODEC(ZSTD(1)) AFTER `enrichments.custom_ioc_domain_threat_type`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.custom_ioc_domain_confidence` UInt8 CODEC(T64, ZSTD(1)) AFTER `enrichments.custom_ioc_domain_malware`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.custom_ioc_hash_threat_type` String CODEC(ZSTD(1)) AFTER `enrichments.custom_ioc_domain_confidence`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.custom_ioc_hash_malware` String CODEC(ZSTD(1)) AFTER `enrichments.custom_ioc_hash_threat_type`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.custom_ioc_hash_confidence` UInt8 CODEC(T64, ZSTD(1)) AFTER `enrichments.custom_ioc_hash_malware`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.custom_ioc_url_threat_type` String CODEC(ZSTD(1)) AFTER `enrichments.custom_ioc_hash_confidence`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.custom_ioc_url_malware` String CODEC(ZSTD(1)) AFTER `enrichments.custom_ioc_url_threat_type`;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `enrichments.custom_ioc_url_confidence` UInt8 CODEC(T64, ZSTD(1)) AFTER `enrichments.custom_ioc_url_malware`;

ALTER TABLE nanosiem.ocsf_logs_raw_mv /* nano:skip-if-unknown-table */
MODIFY QUERY SELECT
    timestamp,
    if(source_type IN ('', 'unknown'), lower(ifNull(toString(event.metadata.log_source), 'unknown')), lower(source_type)) AS source_type,
    id,
    ifNull(accurateCastOrNull(event.`class_uid`, 'UInt32'), 0) AS `class_uid`,
    ifNull(accurateCastOrNull(event.`category_uid`, 'UInt16'), 0) AS `category_uid`,
    ifNull(accurateCastOrNull(event.`activity_id`, 'Int32'), 0) AS `activity_id`,
    ifNull(accurateCastOrNull(event.`type_uid`, 'Int64'), 0) AS `type_uid`,
    ifNull(accurateCastOrNull(event.`severity_id`, 'Int32'), 0) AS `severity_id`,
    ifNull(accurateCastOrNull(event.`status_id`, 'Int32'), 0) AS `status_id`,
    ifNull(accurateCastOrNull(event.`disposition_id`, 'Int32'), 0) AS `disposition_id`,
    ifNull(accurateCastOrNull(event.`action_id`, 'Int32'), 0) AS `action_id`,
    ifNull(accurateCastOrNull(event.`auth_protocol_id`, 'Int32'), 0) AS `auth_protocol_id`,
    ifNull(toString(event.`class_name`), '') AS `class_name`,
    ifNull(toString(event.`category_name`), '') AS `category_name`,
    ifNull(toString(event.`activity_name`), '') AS `activity_name`,
    ifNull(toString(event.`severity`), '') AS `severity`,
    ifNull(toString(event.`status`), '') AS `status`,
    ifNull(toString(event.`metadata`.`version`), '') AS `metadata.version`,
    ifNull(toString(event.`metadata`.`uid`), '') AS `metadata.uid`,
    ifNull(toString(event.`metadata`.`event_code`), '') AS `metadata.event_code`,
    ifNull(toString(event.`metadata`.`product`.`name`), '') AS `metadata.product.name`,
    ifNull(toString(event.`metadata`.`product`.`vendor_name`), '') AS `metadata.product.vendor_name`,
    ifNull(toString(event.`metadata`.`log_name`), '') AS `metadata.log_name`,
    ifNull(toString(event.`metadata`.`log_provider`), '') AS `metadata.log_provider`,
    ifNull(toString(event.`metadata`.`correlation_uid`), '') AS `metadata.correlation_uid`,
    ifNull(toString(event.`message`), '') AS `message`,
    ifNull(toString(event.`raw_data`), '') AS `raw_data`,
    ifNull(toString(event.`actor`.`user`.`name`), '') AS `actor.user.name`,
    ifNull(toString(event.`actor`.`user`.`uid`), '') AS `actor.user.uid`,
    ifNull(toString(event.`actor`.`user`.`domain`), '') AS `actor.user.domain`,
    ifNull(toString(event.`actor`.`user`.`email_addr`), '') AS `actor.user.email_addr`,
    ifNull(toString(event.`user`.`name`), '') AS `user.name`,
    ifNull(toString(event.`user`.`uid`), '') AS `user.uid`,
    lower(ifNull(toString(event.`user`.`domain`), '')) AS `user.domain`,
    ifNull(toString(event.`user`.`email_addr`), '') AS `user.email_addr`,
    lower(ifNull(toString(event.`device`.`hostname`), '')) AS `device.hostname`,
    lower(ifNull(toString(event.`device`.`ip`), '')) AS `device.ip`,
    ifNull(toString(event.`device`.`uid`), '') AS `device.uid`,
    lower(ifNull(toString(event.`src_endpoint`.`ip`), '')) AS `src_endpoint.ip`,
    lower(ifNull(toString(event.`src_endpoint`.`hostname`), '')) AS `src_endpoint.hostname`,
    ifNull(accurateCastOrNull(event.`src_endpoint`.`port`, 'Int32'), 0) AS `src_endpoint.port`,
    lower(ifNull(toString(event.`src_endpoint`.`mac`), '')) AS `src_endpoint.mac`,
    if((ifNull(toString(event.`src_endpoint`.`location`.`country`), '')) AS `_native.src_endpoint.location.country` != '', `_native.src_endpoint.location.country`, if(`src_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'country_code', if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`src_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`src_endpoint.ip`), toUInt64(0))), ''), '')) AS `src_endpoint.location.country`,
    if((ifNull(accurateCastOrNull(event.`src_endpoint`.`autonomous_system`.`number`, 'Int64'), 0)) AS `_native.src_endpoint.autonomous_system.number` != 0, `_native.src_endpoint.autonomous_system.number`, toInt64OrZero(replaceRegexpAll(if(`src_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'asn', if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`src_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`src_endpoint.ip`), toUInt64(0))), ''), ''), '[^0-9]', ''))) AS `src_endpoint.autonomous_system.number`,
    lower(ifNull(toString(event.`dst_endpoint`.`ip`), '')) AS `dst_endpoint.ip`,
    lower(ifNull(toString(event.`dst_endpoint`.`hostname`), '')) AS `dst_endpoint.hostname`,
    ifNull(accurateCastOrNull(event.`dst_endpoint`.`port`, 'Int32'), 0) AS `dst_endpoint.port`,
    lower(ifNull(toString(event.`dst_endpoint`.`mac`), '')) AS `dst_endpoint.mac`,
    if((ifNull(toString(event.`dst_endpoint`.`location`.`country`), '')) AS `_native.dst_endpoint.location.country` != '', `_native.dst_endpoint.location.country`, if(`dst_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'country_code', if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`dst_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`dst_endpoint.ip`), toUInt64(0))), ''), '')) AS `dst_endpoint.location.country`,
    if((ifNull(accurateCastOrNull(event.`dst_endpoint`.`autonomous_system`.`number`, 'Int64'), 0)) AS `_native.dst_endpoint.autonomous_system.number` != 0, `_native.dst_endpoint.autonomous_system.number`, toInt64OrZero(replaceRegexpAll(if(`dst_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'asn', if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`dst_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`dst_endpoint.ip`), toUInt64(0))), ''), ''), '[^0-9]', ''))) AS `dst_endpoint.autonomous_system.number`,
    ifNull(accurateCastOrNull(event.`connection_info`.`protocol_num`, 'Int32'), 0) AS `connection_info.protocol_num`,
    ifNull(accurateCastOrNull(event.`traffic`.`bytes_in`, 'UInt64'), 0) AS `traffic.bytes_in`,
    ifNull(accurateCastOrNull(event.`traffic`.`bytes_out`, 'UInt64'), 0) AS `traffic.bytes_out`,
    ifNull(accurateCastOrNull(event.`traffic`.`packets_in`, 'UInt64'), 0) AS `traffic.packets_in`,
    ifNull(accurateCastOrNull(event.`traffic`.`packets_out`, 'UInt64'), 0) AS `traffic.packets_out`,
    ifNull(toString(event.`process`.`name`), '') AS `process.name`,
    ifNull(toString(event.`process`.`cmd_line`), '') AS `process.cmd_line`,
    ifNull(accurateCastOrNull(event.`process`.`pid`, 'Int64'), 0) AS `process.pid`,
    ifNull(toString(event.`process`.`uid`), '') AS `process.uid`,
    ifNull(toString(event.`process`.`file`.`path`), '') AS `process.file.path`,
    arrayMap(x -> lower(x), arrayMap(x -> ifNull(toString(x), ''), event.`process`.`file`.`hashes`[].`value`)) AS `process.file.hashes.value`,
    ifNull(toString(event.`process`.`parent_process`.`name`), '') AS `process.parent_process.name`,
    ifNull(toString(event.`process`.`parent_process`.`cmd_line`), '') AS `process.parent_process.cmd_line`,
    ifNull(toString(event.`actor`.`process`.`name`), '') AS `actor.process.name`,
    ifNull(toString(event.`actor`.`process`.`cmd_line`), '') AS `actor.process.cmd_line`,
    ifNull(accurateCastOrNull(event.`actor`.`process`.`pid`, 'Int64'), 0) AS `actor.process.pid`,
    ifNull(toString(event.`actor`.`process`.`uid`), '') AS `actor.process.uid`,
    ifNull(toString(event.`actor`.`process`.`file`.`path`), '') AS `actor.process.file.path`,
    arrayMap(x -> lower(x), arrayMap(x -> ifNull(toString(x), ''), event.`actor`.`process`.`file`.`hashes`[].`value`)) AS `actor.process.file.hashes.value`,
    ifNull(toString(event.`file`.`path`), '') AS `file.path`,
    ifNull(toString(event.`file`.`name`), '') AS `file.name`,
    arrayMap(x -> lower(x), arrayMap(x -> ifNull(toString(x), ''), event.`file`.`hashes`[].`value`)) AS `file.hashes.value`,
    ifNull(toString(event.`reg_key`.`path`), '') AS `reg_key.path`,
    ifNull(toString(event.`reg_value`.`path`), '') AS `reg_value.path`,
    ifNull(toString(event.`http_request`.`url`.`url_string`), '') AS `http_request.url.url_string`,
    ifNull(toString(event.`http_request`.`url`.`hostname`), '') AS `http_request.url.hostname`,
    ifNull(toString(event.`http_request`.`url`.`path`), '') AS `http_request.url.path`,
    ifNull(toString(event.`http_request`.`http_method`), '') AS `http_request.http_method`,
    ifNull(toString(event.`http_request`.`user_agent`), '') AS `http_request.user_agent`,
    ifNull(accurateCastOrNull(event.`http_response`.`code`, 'Int32'), 0) AS `http_response.code`,
    ifNull(toString(event.`url`.`url_string`), '') AS `url.url_string`,
    ifNull(toString(event.`url`.`hostname`), '') AS `url.hostname`,
    ifNull(toString(event.`query`.`hostname`), '') AS `query.hostname`,
    arrayMap(x -> ifNull(toString(x), ''), event.`answers`[].`rdata`) AS `answers.rdata`,
    ifNull(toString(event.`api`.`operation`), '') AS `api.operation`,
    ifNull(toString(event.`api`.`service`.`name`), '') AS `api.service.name`,
    ifNull(toString(event.`cloud`.`provider`), '') AS `cloud.provider`,
    ifNull(toString(event.`cloud`.`region`), '') AS `cloud.region`,
    ifNull(toString(event.`cloud`.`account`.`uid`), '') AS `cloud.account.uid`,
    ifNull(toString(event.`session`.`uid`), '') AS `session.uid`,
    lower(ifNull(toString(event.`email`.`from`), '')) AS `email.from`,
    ifNull(toString(event.`email`.`subject`), '') AS `email.subject`,
    arrayMap(x -> lower(x), arrayMap(x -> ifNull(toString(x), ''), if(dynamicType(event.`email`.`to`) LIKE 'Array(%', CAST(event.`email`.`to`, 'Array(Nullable(String))'), if(isNull(event.`email`.`to`), [], [toString(event.`email`.`to`)])))) AS `email.to`,
    ifNull(toString(event.`finding_info`.`uid`), '') AS `finding_info.uid`,
    ifNull(toString(event.`finding_info`.`title`), '') AS `finding_info.title`,
    arrayMap(x -> ifNull(toString(x), ''), event.`observables`[].`value`) AS `observables.value`,
    arrayMap(x -> toUInt16OrZero(x), arrayMap(x -> ifNull(toString(x), ''), event.`observables`[].`type_id`)) AS `observables.type_id`,
    arrayMap(x -> ifNull(toString(x), ''), event.`enrichments`[].`value`) AS `enrichments.value`,
    arrayMap(x -> ifNull(toString(x), ''), event.`enrichments`[].`name`) AS `enrichments.name`,
    arrayMap(x -> ifNull(toString(x), ''), event.`resources`[].`uid`) AS `resources.uid`,
    arrayMap(x -> ifNull(toString(x), ''), event.`vulnerabilities`[].`cve`.`uid`) AS `vulnerabilities.cve.uid`,
    ifNull(toString(event.`actor`.`user`.`type`), '') AS `actor.user.type`,
    ifNull(toString(event.`auth_protocol`), '') AS `auth_protocol`,
    ifNull(accurateCastOrNull(event.`is_mfa`, 'Bool'), false) AS `is_mfa`,
    ifNull(accurateCastOrNull(event.`logon_type_id`, 'Int32'), 0) AS `logon_type_id`,
    ifNull(toString(event.`cloud`.`account`.`name`), '') AS `cloud.account.name`,
    if((ifNull(toString(event.`src_endpoint`.`autonomous_system`.`name`), '')) AS `_native.src_endpoint.autonomous_system.name` != '', `_native.src_endpoint.autonomous_system.name`, if(`src_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'as_name', if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`src_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`src_endpoint.ip`), toUInt64(0))), ''), '')) AS `src_endpoint.autonomous_system.name`,
    if((ifNull(toString(event.`src_endpoint`.`location`.`continent`), '')) AS `_native.src_endpoint.location.continent` != '', `_native.src_endpoint.location.continent`, if(`src_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'continent', if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`src_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`src_endpoint.ip`), toUInt64(0))), ''), '')) AS `src_endpoint.location.continent`,
    if((ifNull(toString(event.`dst_endpoint`.`autonomous_system`.`name`), '')) AS `_native.dst_endpoint.autonomous_system.name` != '', `_native.dst_endpoint.autonomous_system.name`, if(`dst_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'as_name', if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`dst_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`dst_endpoint.ip`), toUInt64(0))), ''), '')) AS `dst_endpoint.autonomous_system.name`,
    if((ifNull(toString(event.`dst_endpoint`.`location`.`continent`), '')) AS `_native.dst_endpoint.location.continent` != '', `_native.dst_endpoint.location.continent`, if(`dst_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'continent', if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`dst_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`dst_endpoint.ip`), toUInt64(0))), ''), '')) AS `dst_endpoint.location.continent`,
    ifNull(accurateCastOrNull(event.`duration`, 'Int64'), 0) AS `duration`,
    ifNull(toString(event.`email`.`message_uid`), '') AS `email.message_uid`,
    ifNull(toString(event.`http_request`.`referrer`), '') AS `http_request.referrer`,
    lower(ifNull(toString(event.`trace`.`uid`), '')) AS `trace.uid`,
    lower(ifNull(toString(event.`trace`.`span`.`uid`), '')) AS `trace.span.uid`,
    arrayMap(x -> ifNull(toString(x), ''), if(dynamicType(event.`http_request`.`url`.`categories`) LIKE 'Array(%', CAST(event.`http_request`.`url`.`categories`, 'Array(Nullable(String))'), if(isNull(event.`http_request`.`url`.`categories`), [], [toString(event.`http_request`.`url`.`categories`)]))) AS `http_request.url.categories`,
    ifNull(toString(event.`metadata`.`product`.`feature`.`name`), '') AS `metadata.product.feature.name`,
    ifNull(toString(event.`module`.`file`.`name`), '') AS `module.file.name`,
    ifNull(toString(event.`module`.`file`.`path`), '') AS `module.file.path`,
    ifNull(toString(event.`reg_value`.`name`), '') AS `reg_value.name`,
    ifNull(toString(event.`reg_value`.`data`), '') AS `reg_value.data`,
    arrayMap(x -> ifNull(toString(x), ''), event.`resources`[].`name`) AS `resources.name`,
    arrayMap(x -> ifNull(toString(x), ''), event.`resources`[].`type`) AS `resources.type`,
    lower(ifNull(toString(arrayFirst(h -> ifNull(accurateCastOrNull(h.algorithm_id, 'Int64'), 0) = 3, event.`process`.`file`.`hashes`[]).value), '')) AS `process.file.hashes.sha256`,
    lower(ifNull(toString(arrayFirst(h -> ifNull(accurateCastOrNull(h.algorithm_id, 'Int64'), 0) = 3, event.`actor`.`process`.`file`.`hashes`[]).value), '')) AS `actor.process.file.hashes.sha256`,
    lower(ifNull(toString(arrayFirst(h -> ifNull(accurateCastOrNull(h.algorithm_id, 'Int64'), 0) = 3, event.`file`.`hashes`[]).value), '')) AS `file.hashes.sha256`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_src_ip_threat_type')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_src_ip_threat_type')), if(((multiIf(`src_endpoint.ip` != '' AND dictHas('nanosiem.ioc_enrichment_dict', `src_endpoint.ip`), `src_endpoint.ip`, '')) AS `_ioc_src_ip_key`) != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', `_ioc_src_ip_key`, ''), '')) AS `enrichments.ioc_src_ip_threat_type`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_src_ip_malware')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_src_ip_malware')), if(`_ioc_src_ip_key` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'malware', `_ioc_src_ip_key`, ''), '')) AS `enrichments.ioc_src_ip_malware`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_src_ip_confidence')) != '', toUInt8OrZero(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_src_ip_confidence'))), if(`_ioc_src_ip_key` != '', toUInt8(least(greatest(dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence_level', `_ioc_src_ip_key`, toInt32(0)), 0), 255)), toUInt8(0))) AS `enrichments.ioc_src_ip_confidence`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_dest_ip_threat_type')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_dest_ip_threat_type')), if(((multiIf(`dst_endpoint.ip` != '' AND dictHas('nanosiem.ioc_enrichment_dict', `dst_endpoint.ip`), `dst_endpoint.ip`, '')) AS `_ioc_dest_ip_key`) != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', `_ioc_dest_ip_key`, ''), '')) AS `enrichments.ioc_dest_ip_threat_type`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_dest_ip_malware')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_dest_ip_malware')), if(`_ioc_dest_ip_key` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'malware', `_ioc_dest_ip_key`, ''), '')) AS `enrichments.ioc_dest_ip_malware`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_dest_ip_confidence')) != '', toUInt8OrZero(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_dest_ip_confidence'))), if(`_ioc_dest_ip_key` != '', toUInt8(least(greatest(dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence_level', `_ioc_dest_ip_key`, toInt32(0)), 0), 255)), toUInt8(0))) AS `enrichments.ioc_dest_ip_confidence`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_domain_threat_type')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_domain_threat_type')), if(((multiIf(lower(`url.hostname`) != '' AND dictHas('nanosiem.ioc_enrichment_dict', lower(`url.hostname`)), lower(`url.hostname`), lower(`http_request.url.hostname`) != '' AND dictHas('nanosiem.ioc_enrichment_dict', lower(`http_request.url.hostname`)), lower(`http_request.url.hostname`), lower(`query.hostname`) != '' AND dictHas('nanosiem.ioc_enrichment_dict', lower(`query.hostname`)), lower(`query.hostname`), '')) AS `_ioc_domain_key`) != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', `_ioc_domain_key`, ''), '')) AS `enrichments.ioc_domain_threat_type`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_domain_malware')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_domain_malware')), if(`_ioc_domain_key` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'malware', `_ioc_domain_key`, ''), '')) AS `enrichments.ioc_domain_malware`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_domain_confidence')) != '', toUInt8OrZero(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_domain_confidence'))), if(`_ioc_domain_key` != '', toUInt8(least(greatest(dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence_level', `_ioc_domain_key`, toInt32(0)), 0), 255)), toUInt8(0))) AS `enrichments.ioc_domain_confidence`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_hash_threat_type')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_hash_threat_type')), if(((arrayFirst(h -> dictHas('nanosiem.ioc_enrichment_dict', h), arraySlice(arrayConcat(arrayFilter((v, a) -> multiIf(a = 1, length(v) = 32, a = 2, length(v) = 40, a = 3, length(v) = 64, 0) AND match(v, '^[0-9a-f]+$'), arraySlice(`file.hashes.value`, 1, 16), arrayMap(x -> ifNull(accurateCastOrNull(x, 'Int64'), 0), arraySlice(event.`file`.`hashes`[].`algorithm_id`, 1, 16))), arrayFilter((v, a) -> multiIf(a = 1, length(v) = 32, a = 2, length(v) = 40, a = 3, length(v) = 64, 0) AND match(v, '^[0-9a-f]+$'), arraySlice(`process.file.hashes.value`, 1, 16), arrayMap(x -> ifNull(accurateCastOrNull(x, 'Int64'), 0), arraySlice(event.`process`.`file`.`hashes`[].`algorithm_id`, 1, 16))), arrayFilter((v, a) -> multiIf(a = 1, length(v) = 32, a = 2, length(v) = 40, a = 3, length(v) = 64, 0) AND match(v, '^[0-9a-f]+$'), arraySlice(`actor.process.file.hashes.value`, 1, 16), arrayMap(x -> ifNull(accurateCastOrNull(x, 'Int64'), 0), arraySlice(event.`actor`.`process`.`file`.`hashes`[].`algorithm_id`, 1, 16)))), 1, 16))) AS `_ioc_hash_key`) != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', `_ioc_hash_key`, ''), '')) AS `enrichments.ioc_hash_threat_type`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_hash_malware')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_hash_malware')), if(`_ioc_hash_key` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'malware', `_ioc_hash_key`, ''), '')) AS `enrichments.ioc_hash_malware`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_hash_confidence')) != '', toUInt8OrZero(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_hash_confidence'))), if(`_ioc_hash_key` != '', toUInt8(least(greatest(dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence_level', `_ioc_hash_key`, toInt32(0)), 0), 255)), toUInt8(0))) AS `enrichments.ioc_hash_confidence`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_url_threat_type')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_url_threat_type')), if(((multiIf(arrayElement(arrayMap(url_t -> if(position(url_t, '://') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, '://') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, '[') AND position(url_host_port, ']') > 0, position(url_host_port, ']'), if(position(url_host_port, ':') > 0, position(url_host_port, ':') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), '@')]), 1), if(url_tail_pos = 0, '', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, ['/', char(63), '#'])]), 1), [substring(url_t, position(url_t, '://') + 3)]), 1), url_t), [trimBoth(`url.url_string`)]), 1) != '' AND dictHas('nanosiem.ioc_enrichment_dict', arrayElement(arrayMap(url_t -> if(position(url_t, '://') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, '://') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, '[') AND position(url_host_port, ']') > 0, position(url_host_port, ']'), if(position(url_host_port, ':') > 0, position(url_host_port, ':') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), '@')]), 1), if(url_tail_pos = 0, '', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, ['/', char(63), '#'])]), 1), [substring(url_t, position(url_t, '://') + 3)]), 1), url_t), [trimBoth(`url.url_string`)]), 1)), arrayElement(arrayMap(url_t -> if(position(url_t, '://') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, '://') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, '[') AND position(url_host_port, ']') > 0, position(url_host_port, ']'), if(position(url_host_port, ':') > 0, position(url_host_port, ':') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), '@')]), 1), if(url_tail_pos = 0, '', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, ['/', char(63), '#'])]), 1), [substring(url_t, position(url_t, '://') + 3)]), 1), url_t), [trimBoth(`url.url_string`)]), 1), arrayElement(arrayMap(url_t -> if(position(url_t, '://') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, '://') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, '[') AND position(url_host_port, ']') > 0, position(url_host_port, ']'), if(position(url_host_port, ':') > 0, position(url_host_port, ':') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), '@')]), 1), if(url_tail_pos = 0, '', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, ['/', char(63), '#'])]), 1), [substring(url_t, position(url_t, '://') + 3)]), 1), url_t), [trimBoth(`http_request.url.url_string`)]), 1) != '' AND dictHas('nanosiem.ioc_enrichment_dict', arrayElement(arrayMap(url_t -> if(position(url_t, '://') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, '://') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, '[') AND position(url_host_port, ']') > 0, position(url_host_port, ']'), if(position(url_host_port, ':') > 0, position(url_host_port, ':') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), '@')]), 1), if(url_tail_pos = 0, '', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, ['/', char(63), '#'])]), 1), [substring(url_t, position(url_t, '://') + 3)]), 1), url_t), [trimBoth(`http_request.url.url_string`)]), 1)), arrayElement(arrayMap(url_t -> if(position(url_t, '://') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, '://') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, '[') AND position(url_host_port, ']') > 0, position(url_host_port, ']'), if(position(url_host_port, ':') > 0, position(url_host_port, ':') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), '@')]), 1), if(url_tail_pos = 0, '', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, ['/', char(63), '#'])]), 1), [substring(url_t, position(url_t, '://') + 3)]), 1), url_t), [trimBoth(`http_request.url.url_string`)]), 1), '')) AS `_ioc_url_key`) != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', `_ioc_url_key`, ''), '')) AS `enrichments.ioc_url_threat_type`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_url_malware')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_url_malware')), if(`_ioc_url_key` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'malware', `_ioc_url_key`, ''), '')) AS `enrichments.ioc_url_malware`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_url_confidence')) != '', toUInt8OrZero(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_url_confidence'))), if(`_ioc_url_key` != '', toUInt8(least(greatest(dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence_level', `_ioc_url_key`, toInt32(0)), 0), 255)), toUInt8(0))) AS `enrichments.ioc_url_confidence`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_confidence')) != '', toUInt8OrZero(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_confidence'))), greatest(`enrichments.ioc_src_ip_confidence`, `enrichments.ioc_dest_ip_confidence`, `enrichments.ioc_domain_confidence`, `enrichments.ioc_hash_confidence`, `enrichments.ioc_url_confidence`)) AS `enrichments.ioc_confidence`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_tags')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_tags')), multiIf(`_ioc_src_ip_key` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'tags', `_ioc_src_ip_key`, ''), `_ioc_dest_ip_key` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'tags', `_ioc_dest_ip_key`, ''), `_ioc_domain_key` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'tags', `_ioc_domain_key`, ''), `_ioc_hash_key` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'tags', `_ioc_hash_key`, ''), `_ioc_url_key` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'tags', `_ioc_url_key`, ''), '')) AS `enrichments.ioc_tags`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_source')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_source')), multiIf(`_ioc_src_ip_key` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'source_id', `_ioc_src_ip_key`, ''), `_ioc_dest_ip_key` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'source_id', `_ioc_dest_ip_key`, ''), `_ioc_domain_key` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'source_id', `_ioc_domain_key`, ''), `_ioc_hash_key` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'source_id', `_ioc_hash_key`, ''), `_ioc_url_key` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'source_id', `_ioc_url_key`, ''), '')) AS `enrichments.ioc_source`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_src_ip_threat_type')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_src_ip_threat_type')), if(((multiIf(`src_endpoint.ip` != '' AND dictHas('nanosiem.custom_ioc_enrichment_dict', tuple('ip', `src_endpoint.ip`)), `src_endpoint.ip`, '')) AS `_custom_ioc_src_ip_key`) != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'threat_type', tuple('ip', `_custom_ioc_src_ip_key`), ''), '')) AS `enrichments.custom_ioc_src_ip_threat_type`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_src_ip_malware')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_src_ip_malware')), if(`_custom_ioc_src_ip_key` != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'malware', tuple('ip', `_custom_ioc_src_ip_key`), ''), '')) AS `enrichments.custom_ioc_src_ip_malware`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_src_ip_confidence')) != '', toUInt8OrZero(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_src_ip_confidence'))), if(`_custom_ioc_src_ip_key` != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'confidence', tuple('ip', `_custom_ioc_src_ip_key`), toUInt8(0)), toUInt8(0))) AS `enrichments.custom_ioc_src_ip_confidence`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_dest_ip_threat_type')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_dest_ip_threat_type')), if(((multiIf(`dst_endpoint.ip` != '' AND dictHas('nanosiem.custom_ioc_enrichment_dict', tuple('ip', `dst_endpoint.ip`)), `dst_endpoint.ip`, '')) AS `_custom_ioc_dest_ip_key`) != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'threat_type', tuple('ip', `_custom_ioc_dest_ip_key`), ''), '')) AS `enrichments.custom_ioc_dest_ip_threat_type`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_dest_ip_malware')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_dest_ip_malware')), if(`_custom_ioc_dest_ip_key` != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'malware', tuple('ip', `_custom_ioc_dest_ip_key`), ''), '')) AS `enrichments.custom_ioc_dest_ip_malware`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_dest_ip_confidence')) != '', toUInt8OrZero(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_dest_ip_confidence'))), if(`_custom_ioc_dest_ip_key` != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'confidence', tuple('ip', `_custom_ioc_dest_ip_key`), toUInt8(0)), toUInt8(0))) AS `enrichments.custom_ioc_dest_ip_confidence`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_domain_threat_type')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_domain_threat_type')), if(((multiIf(lower(`url.hostname`) != '' AND dictHas('nanosiem.custom_ioc_enrichment_dict', tuple('domain', lower(`url.hostname`))), lower(`url.hostname`), lower(`http_request.url.hostname`) != '' AND dictHas('nanosiem.custom_ioc_enrichment_dict', tuple('domain', lower(`http_request.url.hostname`))), lower(`http_request.url.hostname`), lower(`query.hostname`) != '' AND dictHas('nanosiem.custom_ioc_enrichment_dict', tuple('domain', lower(`query.hostname`))), lower(`query.hostname`), '')) AS `_custom_ioc_domain_key`) != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'threat_type', tuple('domain', `_custom_ioc_domain_key`), ''), '')) AS `enrichments.custom_ioc_domain_threat_type`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_domain_malware')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_domain_malware')), if(`_custom_ioc_domain_key` != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'malware', tuple('domain', `_custom_ioc_domain_key`), ''), '')) AS `enrichments.custom_ioc_domain_malware`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_domain_confidence')) != '', toUInt8OrZero(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_domain_confidence'))), if(`_custom_ioc_domain_key` != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'confidence', tuple('domain', `_custom_ioc_domain_key`), toUInt8(0)), toUInt8(0))) AS `enrichments.custom_ioc_domain_confidence`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_hash_threat_type')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_hash_threat_type')), if(((arrayFirst(h -> dictHas('nanosiem.custom_ioc_enrichment_dict', tuple('hash', h)), arraySlice(arrayConcat(arrayFilter((v, a) -> multiIf(a = 1, length(v) = 32, a = 2, length(v) = 40, a = 3, length(v) = 64, 0) AND match(v, '^[0-9a-f]+$'), arraySlice(`file.hashes.value`, 1, 16), arrayMap(x -> ifNull(accurateCastOrNull(x, 'Int64'), 0), arraySlice(event.`file`.`hashes`[].`algorithm_id`, 1, 16))), arrayFilter((v, a) -> multiIf(a = 1, length(v) = 32, a = 2, length(v) = 40, a = 3, length(v) = 64, 0) AND match(v, '^[0-9a-f]+$'), arraySlice(`process.file.hashes.value`, 1, 16), arrayMap(x -> ifNull(accurateCastOrNull(x, 'Int64'), 0), arraySlice(event.`process`.`file`.`hashes`[].`algorithm_id`, 1, 16))), arrayFilter((v, a) -> multiIf(a = 1, length(v) = 32, a = 2, length(v) = 40, a = 3, length(v) = 64, 0) AND match(v, '^[0-9a-f]+$'), arraySlice(`actor.process.file.hashes.value`, 1, 16), arrayMap(x -> ifNull(accurateCastOrNull(x, 'Int64'), 0), arraySlice(event.`actor`.`process`.`file`.`hashes`[].`algorithm_id`, 1, 16)))), 1, 16))) AS `_custom_ioc_hash_key`) != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'threat_type', tuple('hash', `_custom_ioc_hash_key`), ''), '')) AS `enrichments.custom_ioc_hash_threat_type`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_hash_malware')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_hash_malware')), if(`_custom_ioc_hash_key` != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'malware', tuple('hash', `_custom_ioc_hash_key`), ''), '')) AS `enrichments.custom_ioc_hash_malware`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_hash_confidence')) != '', toUInt8OrZero(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_hash_confidence'))), if(`_custom_ioc_hash_key` != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'confidence', tuple('hash', `_custom_ioc_hash_key`), toUInt8(0)), toUInt8(0))) AS `enrichments.custom_ioc_hash_confidence`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_url_threat_type')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_url_threat_type')), if(((multiIf(arrayElement(arrayMap(url_t -> if(position(url_t, '://') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, '://') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, '[') AND position(url_host_port, ']') > 0, position(url_host_port, ']'), if(position(url_host_port, ':') > 0, position(url_host_port, ':') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), '@')]), 1), if(url_tail_pos = 0, '', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, ['/', char(63), '#'])]), 1), [substring(url_t, position(url_t, '://') + 3)]), 1), url_t), [trimBoth(`url.url_string`)]), 1) != '' AND dictHas('nanosiem.custom_ioc_enrichment_dict', tuple('url', arrayElement(arrayMap(url_t -> if(position(url_t, '://') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, '://') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, '[') AND position(url_host_port, ']') > 0, position(url_host_port, ']'), if(position(url_host_port, ':') > 0, position(url_host_port, ':') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), '@')]), 1), if(url_tail_pos = 0, '', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, ['/', char(63), '#'])]), 1), [substring(url_t, position(url_t, '://') + 3)]), 1), url_t), [trimBoth(`url.url_string`)]), 1))), arrayElement(arrayMap(url_t -> if(position(url_t, '://') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, '://') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, '[') AND position(url_host_port, ']') > 0, position(url_host_port, ']'), if(position(url_host_port, ':') > 0, position(url_host_port, ':') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), '@')]), 1), if(url_tail_pos = 0, '', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, ['/', char(63), '#'])]), 1), [substring(url_t, position(url_t, '://') + 3)]), 1), url_t), [trimBoth(`url.url_string`)]), 1), arrayElement(arrayMap(url_t -> if(position(url_t, '://') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, '://') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, '[') AND position(url_host_port, ']') > 0, position(url_host_port, ']'), if(position(url_host_port, ':') > 0, position(url_host_port, ':') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), '@')]), 1), if(url_tail_pos = 0, '', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, ['/', char(63), '#'])]), 1), [substring(url_t, position(url_t, '://') + 3)]), 1), url_t), [trimBoth(`http_request.url.url_string`)]), 1) != '' AND dictHas('nanosiem.custom_ioc_enrichment_dict', tuple('url', arrayElement(arrayMap(url_t -> if(position(url_t, '://') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, '://') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, '[') AND position(url_host_port, ']') > 0, position(url_host_port, ']'), if(position(url_host_port, ':') > 0, position(url_host_port, ':') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), '@')]), 1), if(url_tail_pos = 0, '', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, ['/', char(63), '#'])]), 1), [substring(url_t, position(url_t, '://') + 3)]), 1), url_t), [trimBoth(`http_request.url.url_string`)]), 1))), arrayElement(arrayMap(url_t -> if(position(url_t, '://') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, '://') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, '[') AND position(url_host_port, ']') > 0, position(url_host_port, ']'), if(position(url_host_port, ':') > 0, position(url_host_port, ':') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), '@')]), 1), if(url_tail_pos = 0, '', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, ['/', char(63), '#'])]), 1), [substring(url_t, position(url_t, '://') + 3)]), 1), url_t), [trimBoth(`http_request.url.url_string`)]), 1), '')) AS `_custom_ioc_url_key`) != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'threat_type', tuple('url', `_custom_ioc_url_key`), ''), '')) AS `enrichments.custom_ioc_url_threat_type`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_url_malware')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_url_malware')), if(`_custom_ioc_url_key` != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'malware', tuple('url', `_custom_ioc_url_key`), ''), '')) AS `enrichments.custom_ioc_url_malware`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_url_confidence')) != '', toUInt8OrZero(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_ioc_url_confidence'))), if(`_custom_ioc_url_key` != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'confidence', tuple('url', `_custom_ioc_url_key`), toUInt8(0)), toUInt8(0))) AS `enrichments.custom_ioc_url_confidence`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_src_ip_tags')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_src_ip_tags')), if(`src_endpoint.ip` != '', arrayStringConcat(dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('ip', `src_endpoint.ip`), []), ', '), '')) AS `enrichments.custom_src_ip_tags`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_dest_ip_tags')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_dest_ip_tags')), if(`dst_endpoint.ip` != '', arrayStringConcat(dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('ip', `dst_endpoint.ip`), []), ', '), '')) AS `enrichments.custom_dest_ip_tags`,
    toUInt32(length(toJSONString(event))) AS `event_bytes`,
    event,
    event.^unmapped AS `unmapped`
FROM nanosiem.ocsf_logs_raw;

CREATE OR REPLACE DICTIONARY nanosiem.ioc_enrichment_dict
(
    ioc_value String,
    ioc_type String DEFAULT '',
    source_id String DEFAULT '',
    threat_type String DEFAULT '',
    malware String DEFAULT '',
    confidence_level Int32 DEFAULT 0,
    tags String DEFAULT ''
)
PRIMARY KEY ioc_value
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT if(ioc_type = \'url\', arrayElement(arrayMap(url_t -> if(position(url_t, \'://\') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, \'://\') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, \'[\') AND position(url_host_port, \']\') > 0, position(url_host_port, \']\'), if(position(url_host_port, \':\') > 0, position(url_host_port, \':\') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), \'@\')]), 1), if(url_tail_pos = 0, \'\', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, [\'/\', char(63), \'#\'])]), 1), [substring(url_t, position(url_t, \'://\') + 3)]), 1), url_t), [trimBoth(ioc_value)]), 1), lower(ioc_value)) AS ioc_value, ioc_type, source_id, threat_type, malware, confidence_level, tags FROM nanosiem.ioc_enrichment_dict_staging'
))
LIFETIME(MIN 60 MAX 300)
LAYOUT(HASHED());

CREATE OR REPLACE DICTIONARY nanosiem.custom_ioc_enrichment_dict
(
    key_type String,
    key_value String,
    threat_type String,
    malware String,
    confidence UInt8,
    tags Array(String),
    enrichment_names Array(String)
)
PRIMARY KEY key_type, key_value
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT key_type, if(key_type = \'url\', arrayElement(arrayMap(url_t -> if(position(url_t, \'://\') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, \'://\') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, \'[\') AND position(url_host_port, \']\') > 0, position(url_host_port, \']\'), if(position(url_host_port, \':\') > 0, position(url_host_port, \':\') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), \'@\')]), 1), if(url_tail_pos = 0, \'\', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, [\'/\', char(63), \'#\'])]), 1), [substring(url_t, position(url_t, \'://\') + 3)]), 1), url_t), [trimBoth(key_value)]), 1), lower(key_value)) AS key_value, threat_type, malware, confidence, tags, enrichment_names FROM nanosiem.custom_ioc_enrichment_dict_staging'
))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 300);

GRANT dictGet ON nanosiem.custom_ioc_enrichment_dict TO nanosiem_ingest;

GRANT SELECT ON nanosiem.ip_prevalence_source_agg TO nanosiem_ingest;

GRANT SELECT ON nanosiem.hash_prevalence_source_agg TO nanosiem_ingest;

GRANT SELECT ON nanosiem.domain_prevalence_source_agg TO nanosiem_ingest;
