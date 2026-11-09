-- =============================================================================
-- nano — OCSF ClickHouse store (version-agnostic; NAN-4903)
-- =============================================================================
--
-- Design: docs/design/OCSF-CLICKHOUSE.md (options matrix, measurements, the
-- "OCSF 2.0 ships" runbook, nPL field resolution, UDM feature mapping).
--
-- ONE TABLE FOR EVERY OCSF VERSION. nanosiem.ocsf_logs is not a "1.9 table":
--   * every row keeps its own `metadata.version`;
--   * the full OCSF object is stored in `event JSON` (native typed subcolumns,
--     arrays of objects queryable as event.a[].b), minus the promoted scalars,
--     which are SKIPped there and stored exactly once in their typed column;
--   * vendor fields the parser did not map stay in `unmapped JSON`;
--   * ~120 hot paths are promoted to typed columns for indexes and the sort key.
--
-- EVOLUTION IS ADDITIVE. A new OCSF version needs no new table, rewrite or
-- backfill: new attributes are queryable from `event` the day a parser emits
-- them (field resolution consults the embedded OCSF contracts in
-- nanosiem-core/src/schema/ocsf_contracts/). Promoting a path later is a
-- numbered migration:
--     ALTER TABLE nanosiem.ocsf_logs ADD COLUMN `x.y` T MATERIALIZED <expr over event>;
--     ALTER TABLE nanosiem.ocsf_logs ADD INDEX ...;
-- Old parts compute the column from `event` on read (a metadata-only ALTER).
-- Never MODIFY the `event` column's type parameters: that rewrites every part.
--
-- GENERATED. The landing tables, the storage table and the derivation MV are
-- generated from nanosiem-core/docs/ocsf/events/promoted.json by
-- scripts/gen-ocsf-ddl.py (`--check` in tests). Everything after the
-- @generated block (prevalence, entity, identity, telemetry MVs) is
-- hand-maintained.
--
-- SINGLE TENANT. One deployment = one tenant = one ClickHouse: no tenant_id,
-- no tenant partitioning, no row policies by tenant.
--
-- QUERY RULES (CLAUDE.md): one WHERE carrying the time bounds, never an explicit
-- PREWHERE; `lower(col)` text/bloom index forms; daily partitions; 365-day TTL.
-- =============================================================================

-- @generated begin: scripts/gen-ocsf-ddl.py from nanosiem-core/docs/ocsf/events/promoted.json (do not edit)
CREATE DATABASE IF NOT EXISTS nanosiem;

CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs_raw
(
    -- Writers (Vector, Tenzir, audit emitter, findings) send {event, source_type}.
    `event` JSON(max_dynamic_paths = 1024) DEFAULT '{}',
    `timestamp` DateTime64(3, 'UTC') DEFAULT multiIf(
            ifNull(accurateCastOrNull(event.time, 'Int64'), 0) >= 100000000000000,
                fromUnixTimestamp64Milli(intDiv(accurateCastOrNull(event.time, 'Int64'), 1000), 'UTC'),
            ifNull(accurateCastOrNull(event.time, 'Int64'), 0) >= 10000000000,
                fromUnixTimestamp64Milli(accurateCastOrNull(event.time, 'Int64'), 'UTC'),
            ifNull(accurateCastOrNull(event.time, 'Int64'), 0) > 0,
                fromUnixTimestamp64Milli(accurateCastOrNull(event.time, 'Int64') * 1000, 'UTC'),
            parseDateTime64BestEffortOrZero(ifNull(toString(event.time), ''), 3, 'UTC') != toDateTime64(0, 3, 'UTC'),
                parseDateTime64BestEffortOrZero(ifNull(toString(event.time), ''), 3, 'UTC'),
            now64(3, 'UTC')),
    `source_type` LowCardinality(String) DEFAULT lower(ifNull(toString(event.metadata.log_source), 'unknown')),
    `id` UUID DEFAULT generateUUIDv7()
)
ENGINE = Null
;

CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs_native_raw
(
    `event` JSON DEFAULT '{}',
    `source_type` String DEFAULT 'unknown'
)
ENGINE = Null
;

CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs
(
    /* nano:zk-path-name=ocsf_logs_v180 */
    `timestamp` DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    `_inserted_at` DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    `id` UUID DEFAULT generateUUIDv7() CODEC(ZSTD(1)),
    `source_type` LowCardinality(String) CODEC(ZSTD(1)),
    `class_uid` UInt32 CODEC(T64, ZSTD(1)),
    `category_uid` UInt16 CODEC(T64, ZSTD(1)),
    `activity_id` Int32 CODEC(T64, ZSTD(1)),
    `type_uid` Int64 CODEC(T64, ZSTD(1)),
    `severity_id` Int32 CODEC(T64, ZSTD(1)),
    `status_id` Int32 CODEC(T64, ZSTD(1)),
    `disposition_id` Int32 CODEC(T64, ZSTD(1)),
    `action_id` Int32 CODEC(T64, ZSTD(1)),
    `auth_protocol_id` Int32 CODEC(T64, ZSTD(1)),
    `class_name` LowCardinality(String) CODEC(ZSTD(1)),
    `category_name` LowCardinality(String) CODEC(ZSTD(1)),
    `activity_name` LowCardinality(String) CODEC(ZSTD(1)),
    `severity` LowCardinality(String) CODEC(ZSTD(1)),
    `status` LowCardinality(String) CODEC(ZSTD(1)),
    `metadata.version` LowCardinality(String) CODEC(ZSTD(1)),
    `metadata.uid` String CODEC(ZSTD(3)),
    `metadata.event_code` LowCardinality(String) CODEC(ZSTD(1)),
    `metadata.product.name` LowCardinality(String) CODEC(ZSTD(1)),
    `metadata.product.vendor_name` LowCardinality(String) CODEC(ZSTD(1)),
    `metadata.log_name` LowCardinality(String) CODEC(ZSTD(1)),
    `metadata.log_provider` LowCardinality(String) CODEC(ZSTD(1)),
    `metadata.correlation_uid` String CODEC(ZSTD(3)),
    `message` String CODEC(ZSTD(3)),
    `raw_data` String CODEC(ZSTD(3)),
    `actor.user.name` String CODEC(ZSTD(3)),
    `actor.user.uid` String CODEC(ZSTD(3)),
    `actor.user.domain` LowCardinality(String) CODEC(ZSTD(1)),
    `actor.user.email_addr` String CODEC(ZSTD(3)),
    `user.name` String CODEC(ZSTD(3)),
    `user.uid` String CODEC(ZSTD(3)),
    `user.domain` LowCardinality(String) CODEC(ZSTD(1)),
    `user.email_addr` String CODEC(ZSTD(3)),
    `device.hostname` String CODEC(ZSTD(3)),
    `device.ip` String CODEC(ZSTD(3)),
    `device.uid` String CODEC(ZSTD(3)),
    `src_endpoint.ip` String CODEC(ZSTD(3)),
    `src_endpoint.hostname` String CODEC(ZSTD(3)),
    `src_endpoint.port` Int32 CODEC(T64, ZSTD(1)),
    `src_endpoint.mac` String CODEC(ZSTD(3)),
    `src_endpoint.location.country` LowCardinality(String) CODEC(ZSTD(1)),
    `src_endpoint.autonomous_system.number` Int64 CODEC(T64, ZSTD(1)),
    `dst_endpoint.ip` String CODEC(ZSTD(3)),
    `dst_endpoint.hostname` String CODEC(ZSTD(3)),
    `dst_endpoint.port` Int32 CODEC(T64, ZSTD(1)),
    `dst_endpoint.mac` String CODEC(ZSTD(3)),
    `dst_endpoint.location.country` LowCardinality(String) CODEC(ZSTD(1)),
    `dst_endpoint.autonomous_system.number` Int64 CODEC(T64, ZSTD(1)),
    `connection_info.protocol_num` Int32 CODEC(T64, ZSTD(1)),
    `traffic.bytes_in` UInt64 CODEC(T64, ZSTD(1)),
    `traffic.bytes_out` UInt64 CODEC(T64, ZSTD(1)),
    `traffic.packets_in` UInt64 CODEC(T64, ZSTD(1)),
    `traffic.packets_out` UInt64 CODEC(T64, ZSTD(1)),
    `process.name` String CODEC(ZSTD(3)),
    `process.cmd_line` String CODEC(ZSTD(3)),
    `process.pid` Int64 CODEC(T64, ZSTD(1)),
    `process.uid` String CODEC(ZSTD(3)),
    `process.file.path` String CODEC(ZSTD(3)),
    `process.file.hashes.value` Array(String) CODEC(ZSTD(1)),
    `process.parent_process.name` String CODEC(ZSTD(3)),
    `process.parent_process.cmd_line` String CODEC(ZSTD(3)),
    `actor.process.name` String CODEC(ZSTD(3)),
    `actor.process.cmd_line` String CODEC(ZSTD(3)),
    `actor.process.pid` Int64 CODEC(T64, ZSTD(1)),
    `actor.process.uid` String CODEC(ZSTD(3)),
    `actor.process.file.path` String CODEC(ZSTD(3)),
    `actor.process.file.hashes.value` Array(String) CODEC(ZSTD(1)),
    `file.path` String CODEC(ZSTD(3)),
    `file.name` String CODEC(ZSTD(3)),
    `file.hashes.value` Array(String) CODEC(ZSTD(1)),
    `reg_key.path` String CODEC(ZSTD(3)),
    `reg_value.path` String CODEC(ZSTD(3)),
    `http_request.url.url_string` String CODEC(ZSTD(3)),
    `http_request.url.hostname` String CODEC(ZSTD(3)),
    `http_request.url.path` String CODEC(ZSTD(3)),
    `http_request.http_method` LowCardinality(String) CODEC(ZSTD(1)),
    `http_request.user_agent` String CODEC(ZSTD(3)),
    `http_response.code` Int32 CODEC(T64, ZSTD(1)),
    `url.url_string` String CODEC(ZSTD(3)),
    `url.hostname` String CODEC(ZSTD(3)),
    `query.hostname` String CODEC(ZSTD(3)),
    `answers.rdata` Array(String) CODEC(ZSTD(1)),
    `api.operation` LowCardinality(String) CODEC(ZSTD(1)),
    `api.service.name` LowCardinality(String) CODEC(ZSTD(1)),
    `cloud.provider` LowCardinality(String) CODEC(ZSTD(1)),
    `cloud.region` LowCardinality(String) CODEC(ZSTD(1)),
    `cloud.account.uid` String CODEC(ZSTD(3)),
    `session.uid` String CODEC(ZSTD(3)),
    `email.from` String CODEC(ZSTD(3)),
    `email.subject` String CODEC(ZSTD(3)),
    `email.to` Array(String) CODEC(ZSTD(1)),
    `finding_info.uid` String CODEC(ZSTD(3)),
    `finding_info.title` String CODEC(ZSTD(3)),
    `observables.value` Array(String) CODEC(ZSTD(1)),
    `observables.type_id` Array(UInt16) CODEC(ZSTD(1)),
    `enrichments.value` Array(String) CODEC(ZSTD(1)),
    `enrichments.name` Array(String) CODEC(ZSTD(1)),
    `resources.uid` Array(String) CODEC(ZSTD(1)),
    `vulnerabilities.cve.uid` Array(String) CODEC(ZSTD(1)),
    `actor.user.type` LowCardinality(String) CODEC(ZSTD(1)),
    `auth_protocol` LowCardinality(String) CODEC(ZSTD(1)),
    `is_mfa` Bool CODEC(ZSTD(1)),
    `logon_type_id` Int32 CODEC(T64, ZSTD(1)),
    `cloud.account.name` LowCardinality(String) CODEC(ZSTD(1)),
    `src_endpoint.autonomous_system.name` LowCardinality(String) CODEC(ZSTD(1)),
    `src_endpoint.location.continent` LowCardinality(String) CODEC(ZSTD(1)),
    `dst_endpoint.autonomous_system.name` LowCardinality(String) CODEC(ZSTD(1)),
    `dst_endpoint.location.continent` LowCardinality(String) CODEC(ZSTD(1)),
    `duration` Int64 CODEC(T64, ZSTD(1)),
    `email.message_uid` String CODEC(ZSTD(3)),
    `http_request.referrer` String CODEC(ZSTD(3)),
    `trace.uid` String CODEC(ZSTD(3)),
    `trace.span.uid` String CODEC(ZSTD(3)),
    `http_request.url.categories` Array(String) CODEC(ZSTD(1)),
    `metadata.product.feature.name` LowCardinality(String) CODEC(ZSTD(1)),
    `module.file.name` String CODEC(ZSTD(3)),
    `module.file.path` String CODEC(ZSTD(3)),
    `reg_value.name` String CODEC(ZSTD(3)),
    `reg_value.data` String CODEC(ZSTD(3)),
    `resources.name` Array(String) CODEC(ZSTD(1)),
    `resources.type` Array(String) CODEC(ZSTD(1)),
    -- nano-derived (not OCSF attributes; design doc §6)
    `activity` LowCardinality(String) ALIAS `activity_name`,
    `trace_id` String ALIAS `trace.uid`,
    `span_id` String ALIAS `trace.span.uid`,
    `process.file.hashes.sha256` String CODEC(ZSTD(3)),
    `actor.process.file.hashes.sha256` String CODEC(ZSTD(3)),
    `file.hashes.sha256` String CODEC(ZSTD(3)),
    `enrichments.ioc_src_ip_threat_type` String CODEC(ZSTD(1)),
    `enrichments.ioc_src_ip_malware` String CODEC(ZSTD(1)),
    `enrichments.ioc_src_ip_confidence` UInt8 CODEC(T64, ZSTD(1)),
    `enrichments.ioc_dest_ip_threat_type` String CODEC(ZSTD(1)),
    `enrichments.ioc_dest_ip_malware` String CODEC(ZSTD(1)),
    `enrichments.ioc_dest_ip_confidence` UInt8 CODEC(T64, ZSTD(1)),
    `enrichments.ioc_domain_threat_type` String CODEC(ZSTD(1)),
    `enrichments.ioc_domain_malware` String CODEC(ZSTD(1)),
    `enrichments.ioc_domain_confidence` UInt8 CODEC(T64, ZSTD(1)),
    `enrichments.ioc_hash_threat_type` String CODEC(ZSTD(1)),
    `enrichments.ioc_hash_malware` String CODEC(ZSTD(1)),
    `enrichments.ioc_hash_confidence` UInt8 CODEC(T64, ZSTD(1)),
    `enrichments.ioc_url_threat_type` String CODEC(ZSTD(1)),
    `enrichments.ioc_url_malware` String CODEC(ZSTD(1)),
    `enrichments.ioc_url_confidence` UInt8 CODEC(T64, ZSTD(1)),
    `enrichments.ioc_confidence` UInt8 CODEC(T64, ZSTD(1)),
    `enrichments.ioc_tags` String CODEC(ZSTD(1)),
    `enrichments.ioc_source` String CODEC(ZSTD(1)),
    `enrichments.custom_ioc_src_ip_threat_type` String CODEC(ZSTD(1)),
    `enrichments.custom_ioc_src_ip_malware` String CODEC(ZSTD(1)),
    `enrichments.custom_ioc_src_ip_confidence` UInt8 CODEC(T64, ZSTD(1)),
    `enrichments.custom_ioc_dest_ip_threat_type` String CODEC(ZSTD(1)),
    `enrichments.custom_ioc_dest_ip_malware` String CODEC(ZSTD(1)),
    `enrichments.custom_ioc_dest_ip_confidence` UInt8 CODEC(T64, ZSTD(1)),
    `enrichments.custom_ioc_domain_threat_type` String CODEC(ZSTD(1)),
    `enrichments.custom_ioc_domain_malware` String CODEC(ZSTD(1)),
    `enrichments.custom_ioc_domain_confidence` UInt8 CODEC(T64, ZSTD(1)),
    `enrichments.custom_ioc_hash_threat_type` String CODEC(ZSTD(1)),
    `enrichments.custom_ioc_hash_malware` String CODEC(ZSTD(1)),
    `enrichments.custom_ioc_hash_confidence` UInt8 CODEC(T64, ZSTD(1)),
    `enrichments.custom_ioc_url_threat_type` String CODEC(ZSTD(1)),
    `enrichments.custom_ioc_url_malware` String CODEC(ZSTD(1)),
    `enrichments.custom_ioc_url_confidence` UInt8 CODEC(T64, ZSTD(1)),
    `enrichments.custom_src_ip_tags` String CODEC(ZSTD(1)),
    `enrichments.custom_dest_ip_tags` String CODEC(ZSTD(1)),
    `process_name_unified` String ALIAS if(notEmpty(`process.name`), `process.name`, `actor.process.name`),
    `process_path_unified` String ALIAS if(notEmpty(`process.file.path`), `process.file.path`, `actor.process.file.path`),
    `command_line_unified` String ALIAS if(notEmpty(`process.cmd_line`), `process.cmd_line`, `actor.process.cmd_line`),
    `process_id_unified` Int64 ALIAS if(`process.pid` != 0, `process.pid`, `actor.process.pid`),
    `process_guid_unified` String ALIAS if(notEmpty(`process.uid`), `process.uid`, `actor.process.uid`),
    `process_hash_unified` String ALIAS if(notEmpty(`process.file.hashes.sha256`), `process.file.hashes.sha256`, `actor.process.file.hashes.sha256`),
    `user_unified` String ALIAS if(notEmpty(`user.name`), `user.name`, `actor.user.name`),
    `url_domain_unified` String ALIAS if(notEmpty(`http_request.url.hostname`), `http_request.url.hostname`, `url.hostname`),
    `url_unified` String ALIAS if(notEmpty(`http_request.url.url_string`), `http_request.url.url_string`, `url.url_string`),
    `src_host_unified` String ALIAS if(notEmpty(`src_endpoint.hostname`), `src_endpoint.hostname`, `device.hostname`),
    `prevalence_file_hash` UInt16 MATERIALIZED if(`file.hashes.sha256` != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', `file.hashes.sha256`, toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4),
    `prevalence_process_hash` UInt16 MATERIALIZED if(`process.file.hashes.sha256` != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', `process.file.hashes.sha256`, toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4),
    `prevalence_dest_domain` UInt16 MATERIALIZED if(`dst_endpoint.hostname` != '' AND NOT match(`dst_endpoint.hostname`, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'), dictGetOrDefault('nanosiem.domain_prevalence_dict', 'host_count', lower(`dst_endpoint.hostname`), toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4),
    `prevalence_dest_ip` UInt16 MATERIALIZED if(`dst_endpoint.ip` != '' AND NOT (match(`dst_endpoint.ip`, '^10\\.') OR match(`dst_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') OR match(`dst_endpoint.ip`, '^192\\.168\\.') OR match(`dst_endpoint.ip`, '^127\\.') OR match(`dst_endpoint.ip`, '^169\\.254\\.') OR match(`dst_endpoint.ip`, '^100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.') OR startsWith(`dst_endpoint.ip`, 'fe80:') OR startsWith(`dst_endpoint.ip`, 'fc') OR startsWith(`dst_endpoint.ip`, 'fd') OR `dst_endpoint.ip` = '::1'), dictGetOrDefault('nanosiem.ip_prevalence_dict', 'host_count', `dst_endpoint.ip`, toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4),
    `prevalence_min` UInt16 MATERIALIZED least(if(prevalence_file_hash = 65535, toUInt16(9999), prevalence_file_hash), if(prevalence_process_hash = 65535, toUInt16(9999), prevalence_process_hash), if(prevalence_dest_domain = 65535, toUInt16(9999), prevalence_dest_domain), if(prevalence_dest_ip = 65535, toUInt16(9999), prevalence_dest_ip)) CODEC(T64, LZ4),
    `event_bytes` UInt32 CODEC(T64, LZ4),
    -- the full OCSF object minus promoted scalars (SKIPped: stored once, in their column),
    -- hot unpromoted scalars are typed paths (json_hints.json)
    `event` JSON(max_dynamic_paths = 1024, `action` LowCardinality(Nullable(String)), `actor.process.file.name` Nullable(String), `connection_info.protocol_name` LowCardinality(Nullable(String)), `device.type` LowCardinality(Nullable(String)), `disposition` LowCardinality(Nullable(String)), `dst_endpoint.svc_name` Nullable(String), `firewall_rule.name` Nullable(String), `firewall_rule.uid` Nullable(String), `http_response.status` LowCardinality(Nullable(String)), `logon_type` LowCardinality(Nullable(String)), `metadata.log_level` LowCardinality(Nullable(String)), `metadata.log_source` LowCardinality(Nullable(String)), `metadata.original_event_uid` Nullable(String), `process.file.name` Nullable(String), `query.type` LowCardinality(Nullable(String)), `service.name` Nullable(String), SKIP `class_uid`, SKIP `category_uid`, SKIP `activity_id`, SKIP `type_uid`, SKIP `severity_id`, SKIP `status_id`, SKIP `disposition_id`, SKIP `action_id`, SKIP `auth_protocol_id`, SKIP `class_name`, SKIP `category_name`, SKIP `activity_name`, SKIP `severity`, SKIP `status`, SKIP `metadata.version`, SKIP `metadata.uid`, SKIP `metadata.event_code`, SKIP `metadata.product.name`, SKIP `metadata.product.vendor_name`, SKIP `metadata.log_name`, SKIP `metadata.log_provider`, SKIP `metadata.correlation_uid`, SKIP `message`, SKIP `raw_data`, SKIP `actor.user.name`, SKIP `actor.user.uid`, SKIP `actor.user.domain`, SKIP `actor.user.email_addr`, SKIP `user.name`, SKIP `user.uid`, SKIP `user.domain`, SKIP `user.email_addr`, SKIP `device.hostname`, SKIP `device.ip`, SKIP `device.uid`, SKIP `src_endpoint.ip`, SKIP `src_endpoint.hostname`, SKIP `src_endpoint.port`, SKIP `src_endpoint.mac`, SKIP `src_endpoint.location.country`, SKIP `src_endpoint.autonomous_system.number`, SKIP `dst_endpoint.ip`, SKIP `dst_endpoint.hostname`, SKIP `dst_endpoint.port`, SKIP `dst_endpoint.mac`, SKIP `dst_endpoint.location.country`, SKIP `dst_endpoint.autonomous_system.number`, SKIP `connection_info.protocol_num`, SKIP `traffic.bytes_in`, SKIP `traffic.bytes_out`, SKIP `traffic.packets_in`, SKIP `traffic.packets_out`, SKIP `process.name`, SKIP `process.cmd_line`, SKIP `process.pid`, SKIP `process.uid`, SKIP `process.file.path`, SKIP `process.parent_process.name`, SKIP `process.parent_process.cmd_line`, SKIP `actor.process.name`, SKIP `actor.process.cmd_line`, SKIP `actor.process.pid`, SKIP `actor.process.uid`, SKIP `actor.process.file.path`, SKIP `file.path`, SKIP `file.name`, SKIP `reg_key.path`, SKIP `reg_value.path`, SKIP `http_request.url.url_string`, SKIP `http_request.url.hostname`, SKIP `http_request.url.path`, SKIP `http_request.http_method`, SKIP `http_request.user_agent`, SKIP `http_response.code`, SKIP `url.url_string`, SKIP `url.hostname`, SKIP `query.hostname`, SKIP `api.operation`, SKIP `api.service.name`, SKIP `cloud.provider`, SKIP `cloud.region`, SKIP `cloud.account.uid`, SKIP `session.uid`, SKIP `email.from`, SKIP `email.subject`, SKIP `finding_info.uid`, SKIP `finding_info.title`, SKIP `actor.user.type`, SKIP `auth_protocol`, SKIP `is_mfa`, SKIP `logon_type_id`, SKIP `cloud.account.name`, SKIP `src_endpoint.autonomous_system.name`, SKIP `src_endpoint.location.continent`, SKIP `dst_endpoint.autonomous_system.name`, SKIP `dst_endpoint.location.continent`, SKIP `duration`, SKIP `email.message_uid`, SKIP `http_request.referrer`, SKIP `trace.uid`, SKIP `trace.span.uid`, SKIP `metadata.product.feature.name`, SKIP `module.file.name`, SKIP `module.file.path`, SKIP `reg_value.name`, SKIP `reg_value.data`, SKIP `unmapped`) CODEC(ZSTD(1)),
    `unmapped` JSON(max_dynamic_paths = 256) CODEC(ZSTD(1)),
    INDEX idx_category_uid_minmax `category_uid` TYPE minmax GRANULARITY 1,
    INDEX idx_activity_id_minmax `activity_id` TYPE minmax GRANULARITY 1,
    INDEX idx_type_uid_minmax `type_uid` TYPE minmax GRANULARITY 1,
    INDEX idx_severity_id_minmax `severity_id` TYPE minmax GRANULARITY 1,
    INDEX idx_status_id_minmax `status_id` TYPE minmax GRANULARITY 1,
    INDEX idx_disposition_id_minmax `disposition_id` TYPE minmax GRANULARITY 1,
    INDEX idx_action_id_minmax `action_id` TYPE minmax GRANULARITY 1,
    INDEX idx_auth_protocol_id_minmax `auth_protocol_id` TYPE minmax GRANULARITY 1,
    INDEX idx_class_name_set `class_name` TYPE set(256) GRANULARITY 4,
    INDEX idx_activity_name_set `activity_name` TYPE set(256) GRANULARITY 4,
    INDEX idx_metadata_version_set `metadata.version` TYPE set(256) GRANULARITY 4,
    INDEX idx_metadata_uid_bloom `metadata.uid` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_metadata_event_code_lower_bloom lower(`metadata.event_code`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_metadata_correlation_uid_bloom `metadata.correlation_uid` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_message_words lower(`message`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_raw_data_words lower(`raw_data`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_actor_user_name_lower_bloom lower(`actor.user.name`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_actor_user_uid_lower_bloom lower(`actor.user.uid`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_actor_user_email_addr_lower_bloom lower(`actor.user.email_addr`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_user_name_lower_bloom lower(`user.name`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_user_uid_lower_bloom lower(`user.uid`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_user_email_addr_lower_bloom lower(`user.email_addr`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_device_hostname_bloom `device.hostname` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_device_ip_bloom `device.ip` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_device_uid_lower_bloom lower(`device.uid`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_src_endpoint_ip_bloom `src_endpoint.ip` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_src_endpoint_hostname_bloom `src_endpoint.hostname` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_src_endpoint_port_minmax `src_endpoint.port` TYPE minmax GRANULARITY 1,
    INDEX idx_src_endpoint_mac_bloom `src_endpoint.mac` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_dst_endpoint_ip_bloom `dst_endpoint.ip` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_dst_endpoint_hostname_bloom `dst_endpoint.hostname` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_dst_endpoint_port_minmax `dst_endpoint.port` TYPE minmax GRANULARITY 1,
    INDEX idx_dst_endpoint_mac_bloom `dst_endpoint.mac` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_process_name_lower_bloom lower(`process.name`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_process_cmd_line_words lower(`process.cmd_line`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_process_uid_bloom `process.uid` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_process_file_path_lower_bloom lower(`process.file.path`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_process_file_hashes_value_bloom `process.file.hashes.value` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_process_parent_process_name_lower_bloom lower(`process.parent_process.name`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_process_parent_process_cmd_line_words lower(`process.parent_process.cmd_line`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_actor_process_name_lower_bloom lower(`actor.process.name`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_actor_process_cmd_line_words lower(`actor.process.cmd_line`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_actor_process_uid_bloom `actor.process.uid` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_actor_process_file_path_lower_bloom lower(`actor.process.file.path`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_actor_process_file_hashes_value_bloom `actor.process.file.hashes.value` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_file_path_lower_bloom lower(`file.path`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_file_name_lower_bloom lower(`file.name`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_file_hashes_value_bloom `file.hashes.value` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_reg_key_path_lower_bloom lower(`reg_key.path`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_reg_value_path_lower_bloom lower(`reg_value.path`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_http_request_url_url_string_words lower(`http_request.url.url_string`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_http_request_url_hostname_lower_bloom lower(`http_request.url.hostname`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_http_request_user_agent_words lower(`http_request.user_agent`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_http_response_code_minmax `http_response.code` TYPE minmax GRANULARITY 1,
    INDEX idx_url_url_string_words lower(`url.url_string`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_url_hostname_lower_bloom lower(`url.hostname`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_query_hostname_lower_bloom lower(`query.hostname`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_answers_rdata_lower_bloom arrayMap(x -> lower(x), `answers.rdata`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_api_operation_lower_bloom lower(`api.operation`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_cloud_account_uid_bloom `cloud.account.uid` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_session_uid_bloom `session.uid` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_email_from_bloom `email.from` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_email_subject_words lower(`email.subject`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_email_to_bloom `email.to` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_finding_info_uid_bloom `finding_info.uid` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_finding_info_title_words lower(`finding_info.title`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_observables_value_lower_bloom arrayMap(x -> lower(x), `observables.value`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_enrichments_value_lower_bloom arrayMap(x -> lower(x), `enrichments.value`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_resources_uid_lower_bloom arrayMap(x -> lower(x), `resources.uid`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_vulnerabilities_cve_uid_lower_bloom arrayMap(x -> lower(x), `vulnerabilities.cve.uid`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_logon_type_id_minmax `logon_type_id` TYPE minmax GRANULARITY 1,
    INDEX idx_email_message_uid_bloom `email.message_uid` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_trace_uid_bloom `trace.uid` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_trace_span_uid_bloom `trace.span.uid` TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_module_file_name_lower_bloom lower(`module.file.name`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_module_file_path_lower_bloom lower(`module.file.path`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_reg_value_name_lower_bloom lower(`reg_value.name`) TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_reg_value_data_words lower(`reg_value.data`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_source_type_lower_set lower(source_type) TYPE set(256) GRANULARITY 4,
    INDEX idx_process_name_unified_words lower(if(notEmpty(`process.name`), `process.name`, `actor.process.name`)) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_process_path_unified_words lower(if(notEmpty(`process.file.path`), `process.file.path`, `actor.process.file.path`)) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_command_line_unified_words lower(if(notEmpty(`process.cmd_line`), `process.cmd_line`, `actor.process.cmd_line`)) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_process_id_unified if(`process.pid` != 0, `process.pid`, `actor.process.pid`) TYPE bloom_filter GRANULARITY 4,
    INDEX idx_process_guid_unified_words lower(if(notEmpty(`process.uid`), `process.uid`, `actor.process.uid`)) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_process_hash_unified_words lower(if(notEmpty(`process.file.hashes.sha256`), `process.file.hashes.sha256`, `actor.process.file.hashes.sha256`)) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_user_unified_words lower(if(notEmpty(`user.name`), `user.name`, `actor.user.name`)) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_url_domain_unified_words lower(if(notEmpty(`http_request.url.hostname`), `http_request.url.hostname`, `url.hostname`)) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_url_unified_words lower(if(notEmpty(`http_request.url.url_string`), `http_request.url.url_string`, `url.url_string`)) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_src_host_unified_words lower(if(notEmpty(`src_endpoint.hostname`), `src_endpoint.hostname`, `device.hostname`)) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_prevalence_file_hash prevalence_file_hash TYPE minmax GRANULARITY 1,
    INDEX idx_prevalence_process_hash prevalence_process_hash TYPE minmax GRANULARITY 1,
    INDEX idx_prevalence_dest_domain prevalence_dest_domain TYPE minmax GRANULARITY 1,
    INDEX idx_prevalence_dest_ip prevalence_dest_ip TYPE minmax GRANULARITY 1,
    INDEX idx_prevalence_min prevalence_min TYPE minmax GRANULARITY 1
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (class_uid, source_type, timestamp, `src_endpoint.ip`, cityHash64(id))
SAMPLE BY cityHash64(id)
TTL timestamp + toIntervalDay(365) DELETE WHERE timestamp > '2000-01-01'
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 1000,
    merge_max_dynamic_subcolumns_in_wide_part = 64
;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_logs_raw_mv
TO nanosiem.ocsf_logs
DEFINER = CURRENT_USER
SQL SECURITY DEFINER
AS SELECT
    timestamp,
    if((if(source_type IN ('', 'unknown'), lower(ifNull(toString(event.metadata.log_source), 'unknown')), lower(source_type))) AS `_nano_st` IN ('audit', 'findings'), 'reserved_spoof', `_nano_st`) AS source_type,
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
FROM nanosiem.ocsf_logs_raw
;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_logs_native_raw_mv
TO nanosiem.ocsf_logs_raw
AS SELECT
    event,
    source_type
FROM nanosiem.ocsf_logs_native_raw
;

-- @generated end


-- =============================================================================
-- PREVALENCE INFRASTRUCTURE  (NAN-1248 — asset-card parity)
-- =============================================================================
-- The prevalence summary tables and dicts are SCHEMA-AGNOSTIC: they key on the
-- artifact (hash / domain / ip) regardless of which landing table produced the
-- row. UDM `clickhouse/init.sql` already CREATEs them when nano owns the UDM
-- table; this OCSF bootstrap re-declares them IF NOT EXISTS / CREATE OR REPLACE
-- (idempotent — identical names, columns, layout) so an OCSF-only deployment
-- still has a working prevalence universe. The defs below are copied verbatim
-- from clickhouse/init.sql + clickhouse/110_prevalence_summary_tables.sql; the
-- only OCSF-specific additions are the *_prevalence_summary_mv views at the
-- bottom, which read FROM nanosiem.ocsf_logs and feed the SAME summary tables.
--
-- The prevalence_* MATERIALIZED columns above read these dicts at insert time.
-- ClickHouse resolves dictGetOrDefault lazily, so the columns work once the
-- dicts exist (created here) and accrue counts as the summary MVs populate.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Summary tables (entity-keyed; AggregatingMergeTree). Copied from
-- clickhouse/init.sql / 110_prevalence_summary_tables.sql verbatim.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS nanosiem.hash_prevalence_summary
(
    `file_hash` String,
    `hash_type` LowCardinality(String),
    `host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6)),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6)),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_file_hash file_hash TYPE bloom_filter GRANULARITY 4,
    -- Recency minmax (NAN-1691): explorer rare/new 7d/30d filters on first_seen/last_seen.
    INDEX idx_first_seen first_seen TYPE minmax GRANULARITY 1,
    INDEX idx_last_seen last_seen TYPE minmax GRANULARITY 1
)
ENGINE = AggregatingMergeTree
ORDER BY (file_hash, hash_type)
TTL toDateTime(last_seen) + toIntervalDay(30)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS nanosiem.domain_prevalence_summary
(
    `domain` String,
    `is_subdomain` UInt8,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6)),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6)),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_domain domain TYPE bloom_filter GRANULARITY 4,
    -- Recency minmax (NAN-1691): explorer rare/new 7d/30d filters on first_seen/last_seen.
    INDEX idx_first_seen first_seen TYPE minmax GRANULARITY 1,
    INDEX idx_last_seen last_seen TYPE minmax GRANULARITY 1
)
ENGINE = AggregatingMergeTree
ORDER BY (domain, is_subdomain)
TTL toDateTime(last_seen) + toIntervalDay(30)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS nanosiem.ip_prevalence_summary
(
    `ip` String,
    `is_private` UInt8,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_ip ip TYPE bloom_filter GRANULARITY 4,
    -- Recency minmax (NAN-1691): explorer rare/new 7d/30d filters on first_seen/last_seen.
    INDEX idx_first_seen first_seen TYPE minmax GRANULARITY 1,
    INDEX idx_last_seen last_seen TYPE minmax GRANULARITY 1
)
ENGINE = AggregatingMergeTree
ORDER BY (ip, is_private)
TTL toDateTime(last_seen) + toIntervalDay(30)
SETTINGS index_granularity = 8192;

-- -----------------------------------------------------------------------------
-- Prevalence dictionaries. Copied from clickhouse/init.sql (FRO-243 /
-- NAN-606 / NAN-706 layout). These CACHE dicts deliberately keep
-- KEY-PUSHDOWN sources — they are NOT staged (NAN-1440 reverted NAN-1407's
-- staging for this family): CACHE layouts push the missed keys into the
-- source QUERY, so each miss runs a small, memory-bounded (512 MiB cap,
-- 256 MiB spill, 2 threads — migrations 112/130) aggregation over a handful
-- of keys, while the staging model full-rewrote the entire aggregated
-- keyspace every 10 minutes (83.39M rows / ~1.6 GiB per cycle measured on
-- Saturn — and its seed OOMed the boot-gating migrator at the 512 MiB
-- bound). Rule: full-reload dicts (HASHED/IP_TRIE) get staging indirection;
-- CACHE dicts keep pushdown. HOST/PORT/USER/PASSWORD use the
-- runner-substituted {clickhouse_self_*} placeholders, same as UDM init.sql
-- (never hardcode creds in a numbered/bootstrap file).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE DICTIONARY nanosiem.hash_prevalence_dict
(
    file_hash String,
    host_count UInt16 DEFAULT 9999,
    first_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    last_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    total_occurrences UInt64 DEFAULT 0
)
PRIMARY KEY file_hash
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT file_hash,
                  argMax(host_count, version) AS host_count,
                  argMax(first_seen, version) AS first_seen,
                  argMax(last_seen, version) AS last_seen,
                  argMax(total_occurrences, version) AS total_occurrences
           FROM nanosiem.hash_prevalence_final
           GROUP BY file_hash'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS {prevalence_cache_cells}));

CREATE OR REPLACE DICTIONARY nanosiem.domain_prevalence_dict
(
    domain String,
    host_count UInt16 DEFAULT 9999,
    first_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    last_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    total_occurrences UInt64 DEFAULT 0
)
PRIMARY KEY domain
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT domain,
                  argMax(host_count, version) AS host_count,
                  argMax(first_seen, version) AS first_seen,
                  argMax(last_seen, version) AS last_seen,
                  argMax(total_occurrences, version) AS total_occurrences
           FROM nanosiem.domain_prevalence_final
           GROUP BY domain'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS {prevalence_cache_cells}));

CREATE OR REPLACE DICTIONARY nanosiem.ip_prevalence_dict
(
    ip String,
    host_count UInt16 DEFAULT 9999,
    first_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    last_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    total_occurrences UInt64 DEFAULT 0
)
PRIMARY KEY ip
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT ip,
                  argMax(host_count, version) AS host_count,
                  argMax(first_seen, version) AS first_seen,
                  argMax(last_seen, version) AS last_seen,
                  argMax(total_occurrences, version) AS total_occurrences
           FROM nanosiem.ip_prevalence_final
           GROUP BY ip'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS {prevalence_cache_cells_ip}));

-- -----------------------------------------------------------------------------
-- Prevalence aggregation tables + chained summary MVs (agg -> summary).
-- NAN-4906: CH 26.7+ rejects AggregatingMergeTree plain columns outside the
-- sorting key unless allow_dimensions_outside_sorting_key = 1. Ours (is_subdomain,
-- parent_domain, hash_type, is_private) are functions of the key, so collapsing
-- them on merge is correct. The migrator strips the setting on pre-26.7 servers.
-- Re-declared verbatim from clickhouse/init.sql (NAN-365 layout) so this OCSF
-- bootstrap is SELF-SUFFICIENT for the agg-routed prevalence chain regardless of
-- whether clickhouse/init.sql has run first: the OCSF branch MVs below write
-- into these *_prevalence_agg tables, and the chained *_prevalence_summary_mv
-- views fan the agg states into the entity-keyed *_prevalence_summary tables
-- (the dict source). All IF NOT EXISTS with identical names/columns/layout, so
-- a no-op when clickhouse/init.sql already created them.
-- -----------------------------------------------------------------------------

-- Table: domain_prevalence_agg
CREATE TABLE IF NOT EXISTS nanosiem.domain_prevalence_agg
(
    `domain` String,
    `is_subdomain` UInt8,
    `parent_domain` String,
    `time_bucket` DateTime,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6)),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6)),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_domain domain TYPE bloom_filter GRANULARITY 4,
    INDEX idx_parent_domain parent_domain TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (domain, time_bucket)
TTL time_bucket + toIntervalDay(90)
SETTINGS index_granularity = 8192, allow_dimensions_outside_sorting_key = 1
;

-- Table: hash_prevalence_agg
CREATE TABLE IF NOT EXISTS nanosiem.hash_prevalence_agg
(
    `file_hash` String,
    `hash_type` LowCardinality(String),
    `time_bucket` DateTime,
    `host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6)),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6)),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_file_hash file_hash TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (file_hash, time_bucket)
TTL time_bucket + toIntervalDay(90)
SETTINGS index_granularity = 8192, allow_dimensions_outside_sorting_key = 1
;

-- Table: ip_prevalence_agg
CREATE TABLE IF NOT EXISTS nanosiem.ip_prevalence_agg
(
    `ip` String,
    `direction` LowCardinality(String),
    `is_private` UInt8,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_ip ip TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (ip, direction, time_bucket)
TTL time_bucket + toIntervalDay(90)
SETTINGS index_granularity = 8192, allow_dimensions_outside_sorting_key = 1;

-- Chained summary MVs (agg -> summary, pass-through — AggregatingMergeTree
-- background-merges the uniq states). Verbatim from clickhouse/init.sql.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.hash_prevalence_summary_mv
TO nanosiem.hash_prevalence_summary AS
SELECT
    file_hash,
    hash_type,
    host_count,
    first_seen,
    last_seen,
    total_count
FROM nanosiem.hash_prevalence_agg;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.domain_prevalence_summary_mv
TO nanosiem.domain_prevalence_summary AS
SELECT
    domain,
    is_subdomain,
    source_host_count,
    first_seen,
    last_seen,
    total_count
FROM nanosiem.domain_prevalence_agg;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ip_prevalence_summary_mv
TO nanosiem.ip_prevalence_summary AS
SELECT
    ip,
    is_private,
    source_host_count,
    first_seen,
    last_seen,
    total_count
FROM nanosiem.ip_prevalence_agg;

-- -----------------------------------------------------------------------------
-- OCSF prevalence branch MVs (NAN-1661 — agg-layer bypass fix). Earlier
-- revisions wrote these DIRECTLY into the entity-keyed *_prevalence_summary
-- tables, BYPASSING *_prevalence_agg. Every explorer / rare / new / export /
-- single / bulk / daily-heatmap / scatter surface reads *_prevalence_agg, so on
-- OCSF-profile tenants all of them returned "never seen" even though the
-- summary-sourced dicts worked (which masked the bug). These now write into the
-- *_prevalence_agg tables EXACTLY like the UDM per-branch MVs (init.sql /
-- 129_prevalence_mv_split.sql), and the chained *_prevalence_summary_mv views
-- above fan them into the summary tables via MV chaining — so ONE write path
-- feeds BOTH the agg-reading surfaces AND the summary-sourced dicts.
-- Bodies mirror the UDM per-branch prevalence MVs; only the source columns
-- differ (OCSF nested names). The host-identity expression mirrors UDM
-- (src_host else src_ip else 'unknown'); OCSF's equivalents are
-- src_endpoint.hostname / src_endpoint.ip. MV NAMES ARE UNCHANGED (they retain
-- the historical *_prevalence_summary_* names) so
-- nanosiem-core/tests/aggregation_mv_schema_guard.rs keeps pinning them.
--
-- ⚠ INGEST-CREDENTIAL COUPLING (NAN-1384): ClickHouse checks the INSERTING
-- user's column-level SELECT on nanosiem.ocsf_logs for every column these MVs
-- read while pushing. The INSERT-only `nanosiem_ingest` user (users.d /
-- deploy templates) is granted SELECT on exactly the columns below. If you add
-- an MV over ocsf_logs or widen one's SELECT list, extend that grant in
-- clickhouse/users.d/nanosiem-users.xml + deploy/k8s/clickhouse/clickhouse.yaml
-- + deploy/k8s/{rackspace,aws}-db/clickhouse.yaml.tpl, or direct-writer inserts
-- start failing with ACCESS_DENIED (loud, but an outage).
-- -----------------------------------------------------------------------------

-- ONE MV PER ENTITY BRANCH, never a UNION ALL body: ClickHouse only attaches
-- the insert trigger to the FIRST SELECT of a UNION ALL (NAN-1393; same
-- mechanism as NAN-1386). Branch bodies (validity/TLD filters, cross-branch
-- dedup) mirror the UDM per-branch prevalence MVs in init.sql. Keep in
-- lockstep with clickhouse/129_prevalence_mv_split.sql —
-- nanosiem-core/tests/aggregation_mv_schema_guard.rs enforces equivalence.

-- Hash prevalence (file + process hashes), OCSF columns -> hash_prevalence_summary.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_hash_prevalence_summary_file_hash_mv
TO nanosiem.hash_prevalence_agg
(
    `file_hash` String,
    `hash_type` String,
    `time_bucket` DateTime('UTC'),
    `host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    lower(`file.hashes.sha256`) AS file_hash,
    multiIf(length(`file.hashes.sha256`) = 32, 'md5', length(`file.hashes.sha256`) = 40, 'sha1', length(`file.hashes.sha256`) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`file.hashes.sha256` != '') AND ((length(`file.hashes.sha256`) = 32) OR (length(`file.hashes.sha256`) = 40) OR (length(`file.hashes.sha256`) = 64)) AND match(`file.hashes.sha256`, '^[a-fA-F0-9]+$')
GROUP BY file_hash, hash_type, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_hash_prevalence_summary_process_hash_mv
TO nanosiem.hash_prevalence_agg
(
    `file_hash` String,
    `hash_type` String,
    `time_bucket` DateTime('UTC'),
    `host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    lower(`process.file.hashes.sha256`) AS file_hash,
    multiIf(length(`process.file.hashes.sha256`) = 32, 'md5', length(`process.file.hashes.sha256`) = 40, 'sha1', length(`process.file.hashes.sha256`) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`process.file.hashes.sha256` != '') AND ((length(`process.file.hashes.sha256`) = 32) OR (length(`process.file.hashes.sha256`) = 40) OR (length(`process.file.hashes.sha256`) = 64)) AND match(`process.file.hashes.sha256`, '^[a-fA-F0-9]+$') AND ((`file.hashes.sha256` = '') OR (lower(`file.hashes.sha256`) != lower(`process.file.hashes.sha256`)))
GROUP BY file_hash, hash_type, time_bucket;

-- Domain prevalence (dst_endpoint.hostname / query.hostname / url.hostname),
-- OCSF columns -> domain_prevalence_summary. Validity/TLD filters mirror UDM.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_domain_prevalence_summary_dest_host_mv
TO nanosiem.domain_prevalence_agg
(
    `domain` String,
    `is_subdomain` UInt8,
    `parent_domain` String,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    lower(`dst_endpoint.hostname`) AS domain,
    if(length(splitByChar('.', `dst_endpoint.hostname`)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`dst_endpoint.hostname` != '') AND (position(`dst_endpoint.hostname`, '.') > 0) AND (NOT match(`dst_endpoint.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND (NOT (position(`dst_endpoint.hostname`, ':') > 0)) AND match(`dst_endpoint.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `dst_endpoint.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `dst_endpoint.hostname`)[-1], '^[0-9]+$')) AND (length(`dst_endpoint.hostname`) <= 253)
    AND (lower(splitByChar('.', `dst_endpoint.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_domain_prevalence_summary_query_mv
TO nanosiem.domain_prevalence_agg
(
    `domain` String,
    `is_subdomain` UInt8,
    `parent_domain` String,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    lower(`query.hostname`) AS domain,
    if(length(splitByChar('.', `query.hostname`)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`query.hostname` != '') AND (position(`query.hostname`, '.') > 0) AND (NOT match(`query.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND (NOT (position(`query.hostname`, ':') > 0)) AND match(`query.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `query.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `query.hostname`)[-1], '^[0-9]+$')) AND (length(`query.hostname`) <= 253) AND ((`dst_endpoint.hostname` = '') OR (lower(`dst_endpoint.hostname`) != lower(`query.hostname`)))
    AND (lower(splitByChar('.', `query.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_domain_prevalence_summary_url_mv
TO nanosiem.domain_prevalence_agg
(
    `domain` String,
    `is_subdomain` UInt8,
    `parent_domain` String,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    lower(`url.hostname`) AS domain,
    if(length(splitByChar('.', `url.hostname`)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`url.hostname` != '') AND (position(`url.hostname`, '.') > 0) AND (NOT match(`url.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND match(`url.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `url.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `url.hostname`)[-1], '^[0-9]+$')) AND (length(`url.hostname`) <= 253) AND ((`dst_endpoint.hostname` = '') OR (lower(`dst_endpoint.hostname`) != lower(`url.hostname`))) AND ((`query.hostname` = '') OR (lower(`query.hostname`) != lower(`url.hostname`)))
    AND (lower(splitByChar('.', `url.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket;

-- IP prevalence (dst_endpoint.ip / src_endpoint.ip), OCSF columns ->
-- ip_prevalence_summary. is_private classification mirrors UDM.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_ip_prevalence_summary_dest_ip_mv
TO nanosiem.ip_prevalence_agg
(
    `ip` String,
    `direction` String,
    `is_private` UInt8,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    `dst_endpoint.ip` AS ip,
    'dest' AS direction,
    if(
        match(`dst_endpoint.ip`, '^10\\.') OR
        match(`dst_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') OR
        match(`dst_endpoint.ip`, '^192\\.168\\.') OR
        match(`dst_endpoint.ip`, '^127\\.') OR
        match(`dst_endpoint.ip`, '^169\\.254\\.'),
        1, 0
    ) AS is_private,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE `dst_endpoint.ip` != ''
  AND match(`dst_endpoint.ip`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT match(`dst_endpoint.ip`, '^127\\.')
  AND NOT match(`dst_endpoint.ip`, '^169\\.254\\.')
GROUP BY ip, direction, is_private, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_ip_prevalence_summary_src_ip_mv
TO nanosiem.ip_prevalence_agg
(
    `ip` String,
    `direction` String,
    `is_private` UInt8,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    `src_endpoint.ip` AS ip,
    'src' AS direction,
    if(
        match(`src_endpoint.ip`, '^10\\.') OR
        match(`src_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') OR
        match(`src_endpoint.ip`, '^192\\.168\\.') OR
        match(`src_endpoint.ip`, '^127\\.') OR
        match(`src_endpoint.ip`, '^169\\.254\\.'),
        1, 0
    ) AS is_private,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`dst_endpoint.hostname` != '', `dst_endpoint.hostname`, if(`dst_endpoint.ip` != '', `dst_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE `src_endpoint.ip` != ''
  AND match(`src_endpoint.ip`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT match(`src_endpoint.ip`, '^127\\.')
  AND NOT match(`src_endpoint.ip`, '^169\\.254\\.')
  AND `src_endpoint.ip` != `dst_endpoint.ip`
GROUP BY ip, direction, is_private, time_bucket;

-- -----------------------------------------------------------------------------
-- OCSF aggregation MVs (NAN-1385, G13). Same write-directly-into-the-shared-
-- target pattern as the prevalence MVs above: entity first/last-seen, identity
-- observations (which chains into nat_detection_mv — MV chaining fires
-- downstream MVs on MV-pushed inserts, so NAT detection needs no OCSF-specific
-- MV), cloud Users activity, and per-source telemetry, so data ingested ONLY
-- into ocsf_logs (the direct-write / no-Vector path) reaches every aggregation
-- surface. One MV per entity branch — NEVER a UNION ALL body: ClickHouse only
-- attaches the insert trigger to the first SELECT (NAN-1386).
--
-- Under the transitional Vector dual-write (Vector writes both `logs` and
-- `ocsf_logs`), Vector-lane events are counted by BOTH MV sets — uniq states
-- merge exactly; sum/count aggregates double only while dual-write is in
-- place, same accepted behavior as the prevalence MVs above.
--
-- The ⚠ INGEST-CREDENTIAL COUPLING warning above applies: every column these
-- MVs read is mirrored into the nanosiem_ingest SELECT grant.
-- Migration 128 mirrors this block for existing deployments.
-- -----------------------------------------------------------------------------

-- Entity first/last-seen (asset views), OCSF columns -> entity_time_range_agg.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_time_range_src_ip_mv
TO nanosiem.entity_time_range_agg
(
    `entity_type` String,
    `entity_value` String,
    `time_bucket` DateTime('UTC'),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'src_ip' AS entity_type,
    `src_endpoint.ip` AS entity_value,
    toStartOfHour(timestamp) AS time_bucket,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
WHERE `src_endpoint.ip` != ''
GROUP BY entity_type, entity_value, time_bucket;

-- src_host_unified (src_endpoint.hostname else device.hostname) is already
-- lower()'d at ingest — no extra lower(), matching the agg's lowercase
-- entity_value convention.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_time_range_src_host_mv
TO nanosiem.entity_time_range_agg
(
    `entity_type` String,
    `entity_value` String,
    `time_bucket` DateTime('UTC'),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'src_host' AS entity_type,
    src_host_unified AS entity_value,
    toStartOfHour(timestamp) AS time_bucket,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
WHERE src_host_unified != ''
GROUP BY entity_type, entity_value, time_bucket;

-- user_unified is already lower()'d at ingest (both user.name and
-- actor.user.name materialize through lower()); the lower() here is defensive
-- and keeps the branch self-evidently aligned with the asset reader, which
-- binds lowercased user identifiers.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_time_range_user_mv
TO nanosiem.entity_time_range_agg
(
    `entity_type` String,
    `entity_value` String,
    `time_bucket` DateTime('UTC'),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'user' AS entity_type,
    lower(user_unified) AS entity_value,
    toStartOfHour(timestamp) AS time_bucket,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
WHERE user_unified != ''
GROUP BY entity_type, entity_value, time_bucket;

-- Table: ocsf_entity_dimension_day_agg (NAN-1888)
-- OCSF twin of nanosiem.entity_dimension_day_agg (clickhouse/init.sql) —
-- per-(entity, dimension, value, day) first-seen + count backing the fast path
-- of `| baseline`'s new-to-entity check. A SEPARATE table (not a shared
-- target like entity_time_range_agg) because the reader is PROFILE-KEYED:
-- each lane must see exactly what its raw scan over logs/ocsf_logs sees, and
-- a shared target would double-count under Vector dual-write. MV anchoring
-- mirrors `baseline::dimensions_for`; keep in lockstep with
-- clickhouse/166_baseline_first_seen_agg.sql and
-- scripts/backfill-entity-dimension-day-agg.sh.
--
-- ⚠ INGEST-CREDENTIAL COUPLING (NAN-1384): these MVs read
-- `process_name_unified` and `dst_endpoint.port` (plus already-granted
-- columns) — mirrored into the nanosiem_ingest SELECT grant, see the warning
-- above ocsf_entity_time_range_src_ip_mv.
CREATE TABLE IF NOT EXISTS nanosiem.ocsf_entity_dimension_day_agg
(
    `entity_type` LowCardinality(String),  -- 'host' | 'user' | 'ip'
    `entity_value` String,                  -- lower()ed (ips are ingest-lowercased)
    `dim` LowCardinality(String),           -- UDM-SEMANTIC field name of the dimension
    `val` String,                            -- dimension value, VERBATIM
    `day` Date,
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `event_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_entity_value entity_value TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (entity_type, entity_value, dim, val, day)
TTL day + toIntervalDay(120)
SETTINGS index_granularity = 8192;

-- ONE MV PER ENTITY BRANCH (NAN-1386 — never merge into a UNION ALL view).
-- src_host_unified / dst_endpoint.hostname / user_unified / both ips are
-- already lower()'d at ingest — no extra lower() except the defensive one on
-- user_unified, matching ocsf_entity_time_range_user_mv. ip branches are
-- gated to PRIVATE (RFC1918) entities with throw-free match() regexes
-- (isIPAddressInRange THROWS on malformed values and would fail ingest from
-- inside the MV); the read path routes public-IP entities to the raw scan.

-- host: actor dims (process_name / dest_ip) + src side of the bi-directional
-- user dim.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_dimension_day_host_src_mv
TO nanosiem.ocsf_entity_dimension_day_agg
(
    `entity_type` String,
    `entity_value` String,
    `dim` String,
    `val` String,
    `day` Date,
    `first_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'host' AS entity_type,
    src_host_unified AS entity_value,
    d.1 AS dim,
    d.2 AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
ARRAY JOIN
    [('process_name', toString(process_name_unified)),
     ('dest_ip', toString(`dst_endpoint.ip`)),
     ('user', toString(user_unified))] AS d
WHERE src_host_unified != ''
  AND lower(source_type) != 'audit'
  AND trimBoth(d.2) != '' AND d.2 != '-' AND d.2 != '0' AND lower(d.2) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

-- host: dest side of the user dim; skips dst == src rows (the src-side MV
-- counted those — the raw OR predicate matches such a row ONCE).
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_dimension_day_host_dest_user_mv
TO nanosiem.ocsf_entity_dimension_day_agg
(
    `entity_type` String,
    `entity_value` String,
    `dim` String,
    `val` String,
    `day` Date,
    `first_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'host' AS entity_type,
    `dst_endpoint.hostname` AS entity_value,
    'user' AS dim,
    toString(user_unified) AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
WHERE `dst_endpoint.hostname` != ''
  AND `dst_endpoint.hostname` != src_host_unified
  AND lower(source_type) != 'audit'
  AND trimBoth(user_unified) != '' AND user_unified != '-' AND user_unified != '0' AND lower(user_unified) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

-- user: OCSF has no src_user/dest_user mapping, so the whole account
-- footprint IS user_unified — one branch, matching what the raw scan's
-- profile-resolved predicate collapses to under OCSF.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_dimension_day_user_mv
TO nanosiem.ocsf_entity_dimension_day_agg
(
    `entity_type` String,
    `entity_value` String,
    `dim` String,
    `val` String,
    `day` Date,
    `first_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'user' AS entity_type,
    lower(user_unified) AS entity_value,
    d.1 AS dim,
    d.2 AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
ARRAY JOIN
    [('src_host', toString(src_host_unified)),
     ('src_ip', toString(`src_endpoint.ip`)),
     ('process_name', toString(process_name_unified))] AS d
WHERE user_unified != ''
  AND lower(source_type) != 'audit'
  AND trimBoth(d.2) != '' AND d.2 != '-' AND d.2 != '0' AND lower(d.2) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

-- ip: association dims from the src side (PRIVATE entities only).
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_dimension_day_ip_src_mv
TO nanosiem.ocsf_entity_dimension_day_agg
(
    `entity_type` String,
    `entity_value` String,
    `dim` String,
    `val` String,
    `day` Date,
    `first_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'ip' AS entity_type,
    `src_endpoint.ip` AS entity_value,
    d.1 AS dim,
    d.2 AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
ARRAY JOIN
    [('src_host', toString(src_host_unified)),
     ('dest_port', toString(`dst_endpoint.port`)),
     ('user', toString(user_unified))] AS d
WHERE `src_endpoint.ip` != ''
  AND (match(`src_endpoint.ip`, '^10\\.') OR match(`src_endpoint.ip`, '^192\\.168\\.') OR match(`src_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[01])\\.'))
  AND lower(source_type) != 'audit'
  AND trimBoth(d.2) != '' AND d.2 != '-' AND d.2 != '0' AND lower(d.2) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

-- ip: dest side; skips dst == src rows (the src-side MV counted those).
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_dimension_day_ip_dest_mv
TO nanosiem.ocsf_entity_dimension_day_agg
(
    `entity_type` String,
    `entity_value` String,
    `dim` String,
    `val` String,
    `day` Date,
    `first_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'ip' AS entity_type,
    `dst_endpoint.ip` AS entity_value,
    d.1 AS dim,
    d.2 AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
ARRAY JOIN
    [('src_host', toString(src_host_unified)),
     ('dest_port', toString(`dst_endpoint.port`)),
     ('user', toString(user_unified))] AS d
WHERE `dst_endpoint.ip` != ''
  AND `dst_endpoint.ip` != `src_endpoint.ip`
  AND (match(`dst_endpoint.ip`, '^10\\.') OR match(`dst_endpoint.ip`, '^192\\.168\\.') OR match(`dst_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[01])\\.'))
  AND lower(source_type) != 'audit'
  AND trimBoth(d.2) != '' AND d.2 != '-' AND d.2 != '0' AND lower(d.2) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

-- Identity observations (resolve_identity / lateral movement / NAT via the
-- chained nat_detection_mv). Filters and derivations mirror
-- identity_observations_mv (clickhouse/init.sql): private src IPs only, junk
-- hostnames excluded. `source` falls back to metadata.product.name — THE OCSF
-- source identifier — for direct writers that omit source_type (which
-- DEFAULTs to 'unknown'). namespace/source_priority take the table defaults.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_identity_observations_mv
TO nanosiem.identity_observations
(
    `observed_at` DateTime64(3, 'UTC'),
    `ip` String,
    `hostname` String,
    `fqdn` String,
    `mac` String,
    `user` String,
    `source` LowCardinality(String),
    `domain` LowCardinality(String),
    `ip_type` LowCardinality(String)
)
AS SELECT
    timestamp AS observed_at,
    `src_endpoint.ip` AS ip,
    if(
        position(src_host_unified, '.') > 0 AND position(src_host_unified, '.corp.') > 0,
        substring(src_host_unified, 1, position(src_host_unified, '.') - 1),
        src_host_unified
    ) AS hostname,
    src_host_unified AS fqdn,
    `src_endpoint.mac` AS mac,
    user_unified AS user,
    if(source_type != '' AND source_type != 'unknown', lower(source_type),
       if(`metadata.product.name` != '', lower(`metadata.product.name`), 'unknown')) AS source,
    multiIf(
        position(user_unified, '\\') > 0, substring(user_unified, 1, position(user_unified, '\\') - 1),
        position(src_host_unified, '.corp.') > 0, 'corp',
        ''
    ) AS domain,
    multiIf(
        match(`src_endpoint.ip`, '^10\\.'), 'private',
        match(`src_endpoint.ip`, '^192\\.168\\.'), 'private',
        match(`src_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[01])\\.'), 'private',
        match(`src_endpoint.ip`, '^100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.'), 'vpn',
        match(`src_endpoint.ip`, '^127\\.'), 'loopback',
        'public'
    ) AS ip_type
FROM nanosiem.ocsf_logs
WHERE
    `src_endpoint.ip` != ''
    AND src_host_unified != ''
    AND (
        match(`src_endpoint.ip`, '^10\\.') OR
        match(`src_endpoint.ip`, '^192\\.168\\.') OR
        match(`src_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[01])\\.')
    )
    AND `src_endpoint.ip` NOT IN ('127.0.0.1', '::1', '0.0.0.0')
    AND src_host_unified NOT IN ('localhost', '-', 'unknown', '');

-- Cloud Users activity (cloud investigation Users tab). The agg's `user` join
-- key must carry the SAME values the cloud surface's profile-resolved user
-- column (user_unified, lower()'d at ingest) produces, so it is written
-- as-is with no extra transform. fail = OCSF-native
-- status_id 2 (Failure) OR http_response.code >= 400 (HTTP-shaped classes).
-- delete_count mirrors the query layer's lossy change_type mapping
-- (SearchService::change_type_activity_id: delete -> activity_id 4) scoped to
-- API Activity 6003, where the change semantics live; UDM 'permission_change'
-- is unrepresentable in OCSF -> permission_change_count is 0 on this lane.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_cloud_user_activity_mv
TO nanosiem.cloud_user_activity_agg
(
    `user` String,
    `time_bucket` DateTime,
    `event_count` UInt64,
    `fail_count` UInt64,
    `permission_change_count` UInt64,
    `delete_count` UInt64,
    `mfa_count` UInt64,
    `no_mfa_count` UInt64,
    `distinct_services` AggregateFunction(uniq, String),
    `distinct_regions` AggregateFunction(uniq, String),
    `distinct_ips` AggregateFunction(uniq, String)
)
AS SELECT
    user_unified AS user,
    toStartOfHour(timestamp) AS time_bucket,
    count() AS event_count,
    countIf(`http_response.code` >= 400 OR status_id = 2) AS fail_count,
    toUInt64(0) AS permission_change_count,
    countIf(class_uid = 6003 AND activity_id = 4) AS delete_count,
    countIf(is_mfa = 1) AS mfa_count,
    countIf(is_mfa = 0) AS no_mfa_count,
    uniqState(toString(`api.service.name`)) AS distinct_services,
    uniqState(toString(`cloud.region`)) AS distinct_regions,
    uniqState(`src_endpoint.ip`) AS distinct_ips
FROM nanosiem.ocsf_logs
WHERE `cloud.provider` != '' AND user_unified != ''
GROUP BY user, time_bucket;

-- Per-source 5-minute telemetry rollup (source health / EPS / GB-day).
-- Direct writers that omit source_type land as their OCSF source identifier
-- (metadata.product.name) instead of a single opaque 'unknown' bucket. bytes
-- sums the materialized event_bytes (see the TELEMETRY column above).
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_logs_per_source_5m_mv
TO nanosiem.logs_per_source_5m_v2
(
    `schema_profile` LowCardinality(String),
    `source_type` LowCardinality(String),
    `scope_source_type` LowCardinality(String),
    `scope_source_type_complete` UInt8,
    `bucket_start` DateTime,
    `events` UInt64,
    `bytes` UInt64,
    `last_event_at` DateTime64(6, 'UTC'),
    `first_event_at` DateTime64(6, 'UTC')
)
AS SELECT
    'ocsf' AS schema_profile,
    if(raw_source_type != '' AND raw_source_type != 'unknown', raw_source_type,
       if(product_name != '', product_name, 'unknown')) AS source_type,
    raw_source_type AS scope_source_type,
    toUInt8(1) AS scope_source_type_complete,
    toStartOfFiveMinute(timestamp) AS bucket_start,
    count() AS events,
    sum(event_bytes) AS bytes,
    max(timestamp) AS last_event_at,
    min(timestamp) AS first_event_at
FROM
(
    SELECT
        timestamp,
        event_bytes,
        lower(source_type) AS raw_source_type,
        lower(`metadata.product.name`) AS product_name
    FROM nanosiem.ocsf_logs
)
GROUP BY
    schema_profile,
    source_type,
    scope_source_type,
    scope_source_type_complete,
    bucket_start;

-- =============================================================================
-- NAN-2053: profile/source-attributed prevalence producers
-- =============================================================================
-- Numbered migrations run before this profile overlay on a fresh OCSF install.
-- Migration 170 creates the shared source-attributed targets but necessarily
-- skips these views until ocsf_logs exists. Re-declare them here so fresh OCSF
-- and upgraded OCSF installations converge to the same producer set.

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.hash_prevalence_source_ocsf_mv
TO nanosiem.hash_prevalence_source_agg AS
SELECT
    'ocsf' AS schema_profile,
    lower(trimBoth(source_type)) AS source_type,
    lower(hash_value) AS file_hash,
    multiIf(length(hash_value) = 32, 'md5', length(hash_value) = 40, 'sha1',
            length(hash_value) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`,
                 if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
ARRAY JOIN [`file.hashes.sha256`,
            if(lower(`process.file.hashes.sha256`) != lower(`file.hashes.sha256`),
               `process.file.hashes.sha256`, '')] AS hash_value
WHERE hash_value != ''
  AND length(hash_value) IN (32, 40, 64)
  AND match(hash_value, '^[a-fA-F0-9]+$')
GROUP BY schema_profile, source_type, file_hash, hash_type, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.domain_prevalence_source_ocsf_mv
TO nanosiem.domain_prevalence_source_agg AS
SELECT
    'ocsf' AS schema_profile,
    lower(trimBoth(source_type)) AS source_type,
    lower(domain_value) AS domain,
    if(length(splitByChar('.', domain_value)) > 2, 1, 0) AS is_subdomain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`,
                 if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
ARRAY JOIN [
    `dst_endpoint.hostname`,
    if(lower(`query.hostname`) != lower(`dst_endpoint.hostname`), `query.hostname`, ''),
    if(lower(`url.hostname`) != lower(`dst_endpoint.hostname`)
       AND lower(`url.hostname`) != lower(`query.hostname`), `url.hostname`, '')
] AS domain_value
WHERE domain_value != ''
  AND position(domain_value, '.') > 0
  AND NOT match(domain_value, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT position(domain_value, ':') > 0
  AND match(domain_value, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$')
  AND length(splitByChar('.', domain_value)[-1]) >= 2
  AND NOT match(splitByChar('.', domain_value)[-1], '^[0-9]+$')
  AND length(domain_value) <= 253
  AND lower(splitByChar('.', domain_value)[-1]) NOT IN
      ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa')
GROUP BY schema_profile, source_type, domain, is_subdomain, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ip_prevalence_source_ocsf_mv
TO nanosiem.ip_prevalence_source_agg AS
SELECT
    'ocsf' AS schema_profile,
    lower(trimBoth(source_type)) AS source_type,
    ip_tuple.1 AS ip,
    ip_tuple.2 AS direction,
    if(match(ip, '^10\\.') OR match(ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.')
       OR match(ip, '^192\\.168\\.') OR match(ip, '^127\\.')
       OR match(ip, '^169\\.254\\.'), 1, 0) AS is_private,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(ip_tuple.3) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
ARRAY JOIN [
    (`dst_endpoint.ip`, 'dest',
     if(`src_endpoint.hostname` != '', `src_endpoint.hostname`,
        if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))),
    (if(`src_endpoint.ip` != `dst_endpoint.ip`, `src_endpoint.ip`, ''), 'src',
     if(`dst_endpoint.hostname` != '', `dst_endpoint.hostname`,
        if(`dst_endpoint.ip` != '', `dst_endpoint.ip`, 'unknown')))
] AS ip_tuple
WHERE ip != ''
  AND match(ip, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT match(ip, '^127\\.')
  AND NOT match(ip, '^169\\.254\\.')
GROUP BY schema_profile, source_type, ip, direction, is_private, time_bucket;
