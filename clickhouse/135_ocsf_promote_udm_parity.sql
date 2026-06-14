-- NAN-1465: UDM-parity OCSF promotions — surface registry forensics, web
-- referrer + content category, AWS principal identity, and base-event
-- duration as first-class columns on ocsf_logs (was unmapped/absent).
-- Plain columns populated by ocsf_logs_raw_mv (recreated below with the
-- new JSONExtract lines). ocsf_logs may be absent on UDM-only tenants -> skip.

ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `reg_key.path` String CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `reg_value.name` String CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `reg_value.path` String CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `reg_value.data` String CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `http_request.referrer` String CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `http_request.url.categories` Array(String) DEFAULT [] CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `actor.user.uid` String CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `actor.user.type` LowCardinality(String) CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `duration` UInt32 CODEC(T64, LZ4);

ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD INDEX IF NOT EXISTS idx_reg_key_path_words lower(`reg_key.path`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD INDEX IF NOT EXISTS idx_reg_value_path_words lower(`reg_value.path`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD INDEX IF NOT EXISTS idx_reg_value_name lower(`reg_value.name`) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD INDEX IF NOT EXISTS idx_reg_value_data_words lower(`reg_value.data`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD INDEX IF NOT EXISTS idx_http_referrer_words lower(`http_request.referrer`) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD INDEX IF NOT EXISTS idx_actor_user_uid lower(`actor.user.uid`) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD INDEX IF NOT EXISTS idx_actor_user_type lower(`actor.user.type`) TYPE set(20) GRANULARITY 4;

-- Repoint the ingest MV to populate the new columns.
DROP VIEW IF EXISTS nanosiem.ocsf_logs_raw_mv /* nano:skip-if-unknown-table */;
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_logs_raw_mv /* nano:skip-if-unknown-table */
TO nanosiem.ocsf_logs
AS SELECT
    timestamp,
    source_type,
    id,
    JSONExtractUInt(event, 'class_uid') AS `class_uid`,
    JSONExtractUInt(event, 'category_uid') AS `category_uid`,
    JSONExtractUInt(event, 'activity_id') AS `activity_id`,
    JSONExtractString(event, 'activity_name') AS `activity`,
    JSONExtractUInt(event, 'type_uid') AS `type_uid`,
    JSONExtractUInt(event, 'severity_id') AS `severity_id`,
    JSONExtractString(event, 'severity') AS `severity`,
    JSONExtractUInt(event, 'status_id') AS `status_id`,
    JSONExtractString(event, 'status') AS `status`,
    JSONExtractString(event, 'message') AS `message`,
    event.^unmapped AS `unmapped`,
    lower(JSONExtractString(event, 'src_endpoint', 'ip')) AS `src_endpoint.ip`,
    lower(JSONExtractString(event, 'dst_endpoint', 'ip')) AS `dst_endpoint.ip`,
    toUInt16(JSONExtractUInt(event, 'src_endpoint', 'port')) AS `src_endpoint.port`,
    toUInt16(JSONExtractUInt(event, 'dst_endpoint', 'port')) AS `dst_endpoint.port`,
    lower(JSONExtractString(event, 'src_endpoint', 'mac')) AS `src_endpoint.mac`,
    lower(JSONExtractString(event, 'dst_endpoint', 'mac')) AS `dst_endpoint.mac`,
    lower(JSONExtractString(event, 'src_endpoint', 'hostname')) AS `src_endpoint.hostname`,
    lower(JSONExtractString(event, 'device', 'hostname')) AS `device.hostname`,
    lower(JSONExtractString(event, 'dst_endpoint', 'hostname')) AS `dst_endpoint.hostname`,
    JSONExtractInt(event, 'connection_info', 'protocol_num') AS `connection_info.protocol_num`,
    JSONExtractUInt(event, 'traffic', 'bytes_in') AS `traffic.bytes_in`,
    JSONExtractUInt(event, 'traffic', 'bytes_out') AS `traffic.bytes_out`,
    JSONExtractUInt(event, 'traffic', 'packets_in') AS `traffic.packets_in`,
    JSONExtractUInt(event, 'traffic', 'packets_out') AS `traffic.packets_out`,
    lower(JSONExtractString(event, 'user', 'name')) AS `user.name`,
    lower(JSONExtractString(event, 'actor', 'user', 'name')) AS `actor.user.name`,
    lower(JSONExtractString(event, 'user', 'domain')) AS `user.domain`,
    JSONExtractString(event, 'user', 'uid') AS `user.uid`,
    JSONExtractString(event, 'process', 'name') AS `process.name`,
    JSONExtractString(event, 'process', 'cmd_line') AS `process.cmd_line`,
    JSONExtractUInt(event, 'process', 'pid') AS `process.pid`,
    JSONExtractString(event, 'process', 'uid') AS `process.uid`,
    lower(
        JSONExtractString(
            arrayFirst(
                h -> JSONExtractInt(h, 'algorithm_id') = 3,
                JSONExtractArrayRaw(JSONExtractRaw(event, 'process', 'file', 'hashes'))
            ),
            'value'
        )
    ) AS `process.file.hashes.sha256`,
    JSONExtractString(event, 'process', 'file', 'path') AS `process.file.path`,
    JSONExtractString(event, 'actor', 'process', 'name') AS `actor.process.name`,
    JSONExtractString(event, 'actor', 'process', 'cmd_line') AS `actor.process.cmd_line`,
    JSONExtractUInt(event, 'actor', 'process', 'pid') AS `actor.process.pid`,
    JSONExtractString(event, 'actor', 'process', 'uid') AS `actor.process.uid`,
    lower(
        JSONExtractString(
            arrayFirst(
                h -> JSONExtractInt(h, 'algorithm_id') = 3,
                JSONExtractArrayRaw(JSONExtractRaw(event, 'actor', 'process', 'file', 'hashes'))
            ),
            'value'
        )
    ) AS `actor.process.file.hashes.sha256`,
    JSONExtractString(event, 'actor', 'process', 'file', 'path') AS `actor.process.file.path`,
    JSONExtractString(event, 'file', 'name') AS `file.name`,
    JSONExtractString(event, 'file', 'path') AS `file.path`,
    JSONExtractString(event, 'module', 'file', 'path') AS `module.file.path`,
    JSONExtractString(event, 'module', 'file', 'name') AS `module.file.name`,
    lower(
        JSONExtractString(
            arrayFirst(
                h -> JSONExtractInt(h, 'algorithm_id') = 3,
                JSONExtractArrayRaw(JSONExtractRaw(event, 'file', 'hashes'))
            ),
            'value'
        )
    ) AS `file.hashes.sha256`,
    JSONExtractUInt(event, 'auth_protocol_id') AS `auth_protocol_id`,
    JSONExtractString(event, 'auth_protocol') AS `auth_protocol`,
    JSONExtractString(event, 'session', 'uid') AS `session.uid`,
    toUInt8(JSONExtractBool(event, 'is_mfa')) AS `is_mfa`,
    JSONExtractString(event, 'url', 'hostname') AS `url.hostname`,
    JSONExtractString(event, 'url', 'url_string') AS `url.url_string`,
    JSONExtractString(event, 'http_request', 'http_method') AS `http_request.http_method`,
    JSONExtractString(event, 'http_request', 'url', 'hostname') AS `http_request.url.hostname`,
    JSONExtractString(event, 'http_request', 'url', 'url_string') AS `http_request.url.url_string`,
    JSONExtractString(event, 'http_request', 'url', 'path') AS `http_request.url.path`,
    JSONExtractString(event, 'http_request', 'user_agent') AS `http_request.user_agent`,
    toUInt16(JSONExtractUInt(event, 'http_response', 'code')) AS `http_response.code`,
    -- NAN-1465 promotions
    JSONExtractString(event, 'reg_key', 'path') AS `reg_key.path`,
    JSONExtractString(event, 'reg_value', 'name') AS `reg_value.name`,
    JSONExtractString(event, 'reg_value', 'path') AS `reg_value.path`,
    JSONExtractString(event, 'reg_value', 'data') AS `reg_value.data`,
    JSONExtractString(event, 'http_request', 'referrer') AS `http_request.referrer`,
    JSONExtract(toString(event), 'http_request', 'url', 'categories', 'Array(String)') AS `http_request.url.categories`,
    JSONExtractString(event, 'actor', 'user', 'uid') AS `actor.user.uid`,
    JSONExtractString(event, 'actor', 'user', 'type') AS `actor.user.type`,
    toUInt32(JSONExtractUInt(event, 'duration')) AS `duration`,
    JSONExtractString(event, 'query', 'hostname') AS `query.hostname`,
    JSONExtractString(
        arrayElement(
            JSONExtractArrayRaw(JSONExtractRaw(event, 'answers')),
            1
        ),
        'rdata'
    ) AS `answers.rdata`,
    lower(JSONExtractString(event, 'email', 'from')) AS `email.from`,
    lower(
        JSONExtractString(JSONExtractRaw(event, 'email', 'to'), 1)
    ) AS `email.to`,
    JSONExtractString(event, 'email', 'subject') AS `email.subject`,
    JSONExtractString(event, 'email', 'message_uid') AS `email.message_uid`,
    JSONExtractString(
        arrayElement(
            JSONExtractArrayRaw(JSONExtractRaw(event, 'vulnerabilities')),
            1
        ),
        'cve', 'uid'
    ) AS `vulnerabilities.cve.uid`,
    JSONExtractString(event, 'cloud', 'provider') AS `cloud.provider`,
    JSONExtractString(event, 'cloud', 'account', 'uid') AS `cloud.account.uid`,
    JSONExtractString(event, 'cloud', 'account', 'name') AS `cloud.account.name`,
    JSONExtractString(event, 'cloud', 'region') AS `cloud.region`,
    JSONExtractString(event, 'api', 'service', 'name') AS `api.service.name`,
    JSONExtractString(event, 'api', 'operation') AS `api.operation`,
    JSONExtractString(
        arrayElement(
            JSONExtractArrayRaw(JSONExtractRaw(event, 'resources')),
            1
        ),
        'type'
    ) AS `resources.type`,
    JSONExtractString(
        arrayElement(
            JSONExtractArrayRaw(JSONExtractRaw(event, 'resources')),
            1
        ),
        'uid'
    ) AS `resources.uid`,
    JSONExtractString(
        arrayElement(
            JSONExtractArrayRaw(JSONExtractRaw(event, 'resources')),
            1
        ),
        'name'
    ) AS `resources.name`,
    if(JSONExtractString(event, 'src_endpoint', 'location', 'country') != '', JSONExtractString(event, 'src_endpoint', 'location', 'country'), if(`src_endpoint.ip` != '', if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country_code', toIPv4OrDefault(`src_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country_code', toIPv6OrDefault(`src_endpoint.ip`), '')), '')) AS `src_endpoint.location.country`,
    if(JSONExtractString(event, 'src_endpoint', 'location', 'continent') != '', JSONExtractString(event, 'src_endpoint', 'location', 'continent'), if(`src_endpoint.ip` != '', if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent', toIPv4OrDefault(`src_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent', toIPv6OrDefault(`src_endpoint.ip`), '')), '')) AS `src_endpoint.location.continent`,
    if(JSONExtractUInt(event, 'src_endpoint', 'autonomous_system', 'number') != 0, JSONExtractUInt(event, 'src_endpoint', 'autonomous_system', 'number'), if(`src_endpoint.ip` != '', toUInt32OrZero(replaceRegexpAll(if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'asn', toIPv4OrDefault(`src_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'asn', toIPv6OrDefault(`src_endpoint.ip`), '')), '[^0-9]', '')), 0)) AS `src_endpoint.autonomous_system.number`,
    if(JSONExtractString(event, 'src_endpoint', 'autonomous_system', 'name') != '', JSONExtractString(event, 'src_endpoint', 'autonomous_system', 'name'), if(`src_endpoint.ip` != '', if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_name', toIPv4OrDefault(`src_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_name', toIPv6OrDefault(`src_endpoint.ip`), '')), '')) AS `src_endpoint.autonomous_system.name`,
    if(JSONExtractString(event, 'dst_endpoint', 'location', 'country') != '', JSONExtractString(event, 'dst_endpoint', 'location', 'country'), if(`dst_endpoint.ip` != '', if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country_code', toIPv4OrDefault(`dst_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country_code', toIPv6OrDefault(`dst_endpoint.ip`), '')), '')) AS `dst_endpoint.location.country`,
    if(JSONExtractString(event, 'dst_endpoint', 'location', 'continent') != '', JSONExtractString(event, 'dst_endpoint', 'location', 'continent'), if(`dst_endpoint.ip` != '', if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent', toIPv4OrDefault(`dst_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent', toIPv6OrDefault(`dst_endpoint.ip`), '')), '')) AS `dst_endpoint.location.continent`,
    if(JSONExtractUInt(event, 'dst_endpoint', 'autonomous_system', 'number') != 0, JSONExtractUInt(event, 'dst_endpoint', 'autonomous_system', 'number'), if(`dst_endpoint.ip` != '', toUInt32OrZero(replaceRegexpAll(if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'asn', toIPv4OrDefault(`dst_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'asn', toIPv6OrDefault(`dst_endpoint.ip`), '')), '[^0-9]', '')), 0)) AS `dst_endpoint.autonomous_system.number`,
    if(JSONExtractString(event, 'dst_endpoint', 'autonomous_system', 'name') != '', JSONExtractString(event, 'dst_endpoint', 'autonomous_system', 'name'), if(`dst_endpoint.ip` != '', if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_name', toIPv4OrDefault(`dst_endpoint.ip`), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_name', toIPv6OrDefault(`dst_endpoint.ip`), '')), '')) AS `dst_endpoint.autonomous_system.name`,
    if(JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_src_ip_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ) != '', JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_src_ip_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ), if(`src_endpoint.ip` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', `src_endpoint.ip`, ''), '')) AS `enrichments.ioc_src_ip_threat_type`,
    if(JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_dest_ip_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ) != '', JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_dest_ip_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ), if(`dst_endpoint.ip` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', `dst_endpoint.ip`, ''), '')) AS `enrichments.ioc_dest_ip_threat_type`,
    if(JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_domain_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ) != '', JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_domain_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ), multiIf(`url.hostname` != '' AND dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`url.hostname`), '') != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`url.hostname`), ''), `http_request.url.hostname` != '' AND dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`http_request.url.hostname`), '') != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`http_request.url.hostname`), ''), `query.hostname` != '' AND dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`query.hostname`), '') != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`query.hostname`), ''), '')) AS `enrichments.ioc_domain_threat_type`,
    if(JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_hash_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ) != '', JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'ioc_hash_threat_type',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ), multiIf(`file.hashes.sha256` != '' AND dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`file.hashes.sha256`), '') != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`file.hashes.sha256`), ''), `process.file.hashes.sha256` != '' AND dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`process.file.hashes.sha256`), '') != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`process.file.hashes.sha256`), ''), '')) AS `enrichments.ioc_hash_threat_type`,
    if(JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'custom_src_ip_tags',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ) != '', JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'custom_src_ip_tags',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ), if(`src_endpoint.ip` != '', arrayStringConcat(dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('ip', `src_endpoint.ip`), []), ', '), '')) AS `enrichments.custom_src_ip_tags`,
    if(JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'custom_dest_ip_tags',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ) != '', JSONExtractString(
        arrayFirst(e -> JSONExtractString(e, 'name') = 'custom_dest_ip_tags',
                   JSONExtractArrayRaw(JSONExtractRaw(event, 'enrichments'))),
        'value'
    ), if(`dst_endpoint.ip` != '', arrayStringConcat(dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('ip', `dst_endpoint.ip`), []), ', '), '')) AS `enrichments.custom_dest_ip_tags`,
    JSONExtractString(event, 'metadata', 'product', 'name') AS `metadata.product.name`,
    JSONExtractString(event, 'metadata', 'product', 'vendor_name') AS `metadata.product.vendor_name`,
    JSONExtractString(event, 'metadata', 'product', 'feature', 'name') AS `metadata.product.feature.name`,
    JSONExtractString(event, 'metadata', 'log_name') AS `metadata.log_name`,
    JSONExtractString(event, 'metadata', 'log_provider') AS `metadata.log_provider`,
    JSONExtractString(event, 'metadata', 'uid') AS `metadata.uid`,
    JSONExtractString(event, 'metadata', 'version') AS `metadata.version`,
    JSONExtractString(event, 'metadata', 'correlation_uid') AS `metadata.correlation_uid`,
    length(toString(event)) AS `event_bytes`
FROM nanosiem.ocsf_logs_raw
;
