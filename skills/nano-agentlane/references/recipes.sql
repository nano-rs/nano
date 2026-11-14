-- nano Agent Lane: SQL recipes (native ClickHouse SQL)
--
-- Each recipe starts with `-- @recipe <id>` and runs as one statement.
--   @title   what it answers
--   @param   <name> <ClickHouse type> <example value>   (bind as a query
--            parameter: curl `param_<name>=...`, clickhouse-connect
--            `parameters={...}`, @clickhouse/client `query_params`)
--   @expect  rows | any   (used by the recipe check: `rows` means the seeded
--            test data must return at least one row)
--
-- Every recipe is run, as an Agent Lane token user, against the schema of the
-- nano release named in SKILL.md (scripts/e2e/lanes/agentlane-recipes.sh).
--
-- Single-node installs: query the tables as written (nanosiem.ocsf_logs).
-- Cluster installs: query nanosiem.<table>_distributed instead (for example
-- nanosiem.ocsf_logs_distributed). Run `tables_available` first: if it lists
-- ocsf_logs_distributed, you are on a cluster. Every subquery and join below
-- is written as GLOBAL IN / GLOBAL JOIN. The lane pins
-- distributed_product_mode = 'global', so a plain IN or JOIN across two
-- Distributed tables is rewritten to GLOBAL anyway; writing it explicitly
-- keeps the recipe correct on any ClickHouse and makes the cost visible: the
-- subquery runs once and its whole result is sent to every shard, so keep it
-- small and LIMITed. GLOBAL works on a single node too. Each recipe is run
-- in both forms.
--
-- Rules every recipe follows: a time filter on `timestamp` (or `observed_at`)
-- in the one WHERE clause, no PREWHERE, a LIMIT, values passed as parameters,
-- lowercase literals for the case-insensitive forms.

-- @recipe tables_available
-- @title Which tables this token can read (lists *_distributed on a cluster)
-- @expect rows
SELECT name, engine
FROM system.tables
WHERE database = 'nanosiem'
ORDER BY name
LIMIT 200;

-- @recipe columns_like
-- @title Find columns by name in a table (the lane's live schema)
-- @param table String ocsf_logs
-- @param pattern String %hash%
-- @expect rows
SELECT name, type, default_kind
FROM system.columns
WHERE database = 'nanosiem'
  AND table = {table:String}
  AND name LIKE {pattern:String}
ORDER BY name
LIMIT 200;

-- @recipe source_inventory
-- @title What data is in the lane: events by source and OCSF class, last 24 h
-- @expect rows
SELECT source_type, class_uid, class_name, count() AS events, max(timestamp) AS last_event
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY source_type, class_uid, class_name
ORDER BY events DESC
LIMIT 100;

-- @recipe free_text_token
-- @title Whole-word hunt across message, command lines and raw text (fast: text index)
-- @param needle String mimikatz
-- @expect rows
SELECT timestamp, source_type, class_name,
       src_host_unified AS host, user_unified AS user,
       command_line_unified AS command_line, message
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND (hasToken(lower(message), {needle:String})
       OR hasToken(lower(command_line_unified), {needle:String})
       OR hasToken(lower(raw_data), {needle:String}))
ORDER BY timestamp DESC
LIMIT 100;

-- @recipe free_text_substring
-- @title Substring hunt (part of a word, or text with punctuation)
-- @param fragment String invoke-mimi
-- @expect rows
SELECT timestamp, source_type, src_host_unified AS host, command_line_unified AS command_line
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND class_uid = 1007
  AND lower(command_line_unified) LIKE concat('%', {fragment:String}, '%')
ORDER BY timestamp DESC
LIMIT 100;

-- @recipe top_processes
-- @title Top-N: most launched processes and how many hosts ran them
-- @expect rows
SELECT process_name_unified AS process, count() AS launches, uniq(src_host_unified) AS hosts
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND class_uid = 1007
GROUP BY process
ORDER BY launches DESC
LIMIT 20;

-- @recipe top_talkers
-- @title Top-N: source/destination pairs by bytes sent out
-- @expect rows
SELECT `src_endpoint.ip` AS src, `dst_endpoint.ip` AS dst,
       count() AS connections, sum(`traffic.bytes_out`) AS bytes_out
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND class_uid = 4001
GROUP BY src, dst
ORDER BY bytes_out DESC
LIMIT 20;

-- @recipe failed_auth_spray
-- @title Failed logons per source: brute force and password spray
-- @param min_failures UInt32 10
-- @expect rows
SELECT `src_endpoint.ip` AS src, count() AS failures, uniq(user_unified) AS distinct_users,
       min(timestamp) AS first_seen, max(timestamp) AS last_seen
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND class_uid = 3002
  AND status_id = 2
GROUP BY src
HAVING failures >= {min_failures:UInt32}
ORDER BY failures DESC
LIMIT 50;

-- @recipe timechart_by_class
-- @title Timechart: events per hour per OCSF class
-- @expect rows
SELECT toStartOfInterval(timestamp, INTERVAL 1 HOUR) AS bucket, class_name, count() AS events
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY bucket, class_name
ORDER BY bucket, class_name
LIMIT 1000;

-- @recipe timechart_filled
-- @title Timechart for one class with empty buckets filled with zero
-- @param class_uid UInt32 3002
-- @expect rows
SELECT toStartOfInterval(timestamp, INTERVAL 1 HOUR) AS bucket, count() AS events
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND class_uid = {class_uid:UInt32}
GROUP BY bucket
ORDER BY bucket WITH FILL
  FROM toStartOfInterval(now() - INTERVAL 24 HOUR, INTERVAL 1 HOUR)
  TO now()
  STEP INTERVAL 1 HOUR
LIMIT 1000;

-- @recipe ioc_sweep_observables
-- @title IOC sweep: any IP, domain, hash, user or URL in the OCSF observables list
-- @param iocs Array(String) ['203.0.113.66','c2.bad-domain.example','e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']
-- @expect rows
SELECT timestamp, source_type, class_name, src_host_unified AS host,
       arrayFilter(v -> has({iocs:Array(String)}, lower(v)), `observables.value`) AS matched
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND hasAny(arrayMap(x -> lower(x), `observables.value`), {iocs:Array(String)})
ORDER BY timestamp DESC
LIMIT 200;

-- @recipe ioc_sweep_ips
-- @title IOC sweep: IP addresses on either side of a connection or on the device
-- @param ips Array(String) ['203.0.113.66','192.0.2.77']
-- @expect rows
SELECT `src_endpoint.ip` AS src, `dst_endpoint.ip` AS dst, class_name,
       count() AS events, min(timestamp) AS first_seen, max(timestamp) AS last_seen
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND (`src_endpoint.ip` IN {ips:Array(String)}
       OR `dst_endpoint.ip` IN {ips:Array(String)}
       OR `device.ip` IN {ips:Array(String)})
GROUP BY src, dst, class_name
ORDER BY events DESC
LIMIT 100;

-- @recipe ioc_sweep_hashes
-- @title IOC sweep: file and process hashes (any algorithm)
-- @param hashes Array(String) ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']
-- @expect rows
SELECT timestamp, source_type, src_host_unified AS host, process_name_unified AS process,
       process_hash_unified AS process_sha256, `file.path`
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND (hasAny(`process.file.hashes.value`, {hashes:Array(String)})
       OR hasAny(`actor.process.file.hashes.value`, {hashes:Array(String)})
       OR hasAny(`file.hashes.value`, {hashes:Array(String)}))
ORDER BY timestamp DESC
LIMIT 100;

-- @recipe ioc_sweep_domains
-- @title IOC sweep: domains in DNS queries, URLs and destination host names
-- @param domains Array(String) ['c2.bad-domain.example']
-- @expect rows
SELECT timestamp, source_type, class_name, `src_endpoint.ip` AS src, src_host_unified AS host,
       `query.hostname` AS dns_query, url_domain_unified AS url_domain, `dst_endpoint.hostname` AS dst_host
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND (lower(`query.hostname`) IN {domains:Array(String)}
       OR lower(url_domain_unified) IN {domains:Array(String)}
       OR `dst_endpoint.hostname` IN {domains:Array(String)})
ORDER BY timestamp DESC
LIMIT 100;

-- @recipe process_parent_child
-- @title Office apps spawning shells and script hosts
-- @param parents Array(String) ['winword.exe','excel.exe','powerpnt.exe','outlook.exe']
-- @param children Array(String) ['powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe']
-- @expect rows
SELECT timestamp, src_host_unified AS host, user_unified AS user,
       if(notEmpty(`process.parent_process.name`), `process.parent_process.name`, `actor.process.name`) AS parent,
       `process.name` AS child, `process.cmd_line` AS command_line
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND class_uid = 1007
  AND (lower(`process.parent_process.name`) IN {parents:Array(String)}
       OR lower(`actor.process.name`) IN {parents:Array(String)})
  AND lower(`process.name`) IN {children:Array(String)}
ORDER BY timestamp DESC
LIMIT 100;

-- @recipe event_json_path
-- @title Read an unpromoted OCSF attribute from the `event` JSON column
-- @expect rows
SELECT timestamp, `query.hostname` AS dns_query, toString(event.query.type) AS query_type
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND class_uid = 4003
  AND toString(event.query.type) = 'A'
ORDER BY timestamp DESC
LIMIT 50;

-- @recipe prevalence_hashes
-- @title Prevalence: on how many hosts each hash was seen in the last 30 days, and from which sources
-- @param hashes Array(String) ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']
-- @expect rows
SELECT file_hash, hash_type, uniqMerge(host_count) AS hosts,
       min(first_seen) AS first_seen, max(last_seen) AS last_seen, sum(total_count) AS events,
       groupUniqArray(source_type) AS sources
FROM nanosiem.hash_prevalence_source_summary
WHERE schema_profile = 'ocsf'
  AND file_hash IN {hashes:Array(String)}
GROUP BY file_hash, hash_type
LIMIT 100;

-- @recipe prevalence_domains_new
-- @title Prevalence: domains first seen in the last 24 h, rarest first
-- @expect rows
SELECT domain, uniqMerge(source_host_count) AS hosts,
       min(first_seen) AS first_seen, max(last_seen) AS last_seen, sum(total_count) AS events
FROM nanosiem.domain_prevalence_source_summary
WHERE schema_profile = 'ocsf'
  AND domain GLOBAL IN (
      SELECT DISTINCT domain
      FROM nanosiem.domain_prevalence_source_summary
      WHERE schema_profile = 'ocsf'
        AND first_seen >= now() - INTERVAL 24 HOUR
      LIMIT 10000)
GROUP BY domain
HAVING first_seen >= now() - INTERVAL 24 HOUR
ORDER BY hosts ASC, first_seen DESC
LIMIT 100;

-- @recipe prevalence_ips
-- @title Prevalence: how many distinct sources connected to each IP (as a destination)
-- @param ips Array(String) ['203.0.113.66','198.51.100.1']
-- @expect rows
SELECT ip, uniqMerge(source_host_count) AS hosts,
       min(first_seen) AS first_seen, max(last_seen) AS last_seen, sum(total_count) AS events
FROM nanosiem.ip_prevalence_source_summary
WHERE schema_profile = 'ocsf'
  AND direction = 'dest'
  AND ip IN {ips:Array(String)}
GROUP BY ip
LIMIT 100;

-- @recipe rare_process_hashes
-- @title Rare executables in the window: of the hashes launched in the last 24 h, those seen on few hosts overall
-- @param max_hosts UInt32 2
-- @expect rows
SELECT file_hash AS sha256, uniqMerge(host_count) AS hosts_overall,
       min(first_seen) AS first_seen, max(last_seen) AS last_seen, groupUniqArray(source_type) AS sources
FROM nanosiem.hash_prevalence_source_summary
WHERE schema_profile = 'ocsf'
  AND file_hash GLOBAL IN (
      SELECT DISTINCT process_hash_unified
      FROM nanosiem.ocsf_logs
      WHERE timestamp >= now() - INTERVAL 24 HOUR
        AND class_uid = 1007
        AND process_hash_unified != ''
      LIMIT 10000)
GROUP BY file_hash
HAVING hosts_overall <= {max_hosts:UInt32}
ORDER BY hosts_overall ASC, first_seen DESC
LIMIT 100;

-- @recipe identity_ip_history
-- @title Identity: which host names and users held an internal IP over time
-- @param ip String 10.0.0.10
-- @expect rows
SELECT ip, hostname, user, source,
       min(observed_at) AS first_seen, max(observed_at) AS last_seen, count() AS observations
FROM nanosiem.identity_observations
WHERE observed_at >= now() - INTERVAL 7 DAY
  AND ip = {ip:String}
GROUP BY ip, hostname, user, source
ORDER BY last_seen DESC
LIMIT 50;

-- @recipe identity_asof_join
-- @title Identity as-of join: resolve each event's source IP to the host seen closest before it
-- @param dst String 203.0.113.66
-- @expect rows
SELECT e.timestamp AS timestamp, e.src AS src_ip, i.hostname AS resolved_host, i.user AS resolved_user,
       i.observed_at AS observed_at, dateDiff('second', i.observed_at, e.timestamp) AS age_seconds
FROM (
    SELECT timestamp, `src_endpoint.ip` AS src
    FROM nanosiem.ocsf_logs
    WHERE timestamp >= now() - INTERVAL 24 HOUR
      AND class_uid = 4001
      AND `dst_endpoint.ip` = {dst:String}
) AS e
GLOBAL ASOF LEFT JOIN (
    SELECT ip, observed_at, hostname, user
    FROM nanosiem.identity_observations
    WHERE observed_at >= now() - INTERVAL 48 HOUR
) AS i
ON e.src = i.ip AND e.timestamp >= i.observed_at
ORDER BY timestamp DESC
LIMIT 100;

-- @recipe signals_by_rule
-- @title Detections: which rules fired, how often, on how many entities
-- @expect rows
SELECT rule_id, rule_name, severity, count() AS signals, uniq(risk_entity) AS entities,
       min(timestamp) AS first_fired, max(timestamp) AS last_fired
FROM nanosiem.signals
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY rule_id, rule_name, severity
ORDER BY signals DESC
LIMIT 50;

-- @recipe signal_events
-- @title Detections: the events behind one rule's signals
-- @param rule_id UUID 00000000-0000-7000-8000-000000000001
-- @expect rows
SELECT timestamp, source_type, class_name, src_host_unified AS host, user_unified AS user,
       command_line_unified AS command_line, message
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND id GLOBAL IN (
      SELECT matched_log_id
      FROM nanosiem.signals
      WHERE timestamp >= now() - INTERVAL 24 HOUR
        AND rule_id = {rule_id:UUID})
ORDER BY timestamp DESC
LIMIT 100;

-- @recipe signals_for_entity
-- @title Detections: every signal on one host, user or IP
-- @param entity String 192.0.2.77
-- @expect rows
SELECT timestamp, rule_name, severity, risk_score, risk_entity, matched_log_id
FROM nanosiem.signals
WHERE timestamp >= now() - INTERVAL 7 DAY
  AND risk_entity = {entity:String}
ORDER BY timestamp DESC
LIMIT 100;

-- @recipe udm_logs_sources
-- @title UDM installs only: events by source in the `logs` table
-- @expect any
SELECT source_type, count() AS events, max(timestamp) AS last_event
FROM nanosiem.logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY source_type
ORDER BY events DESC
LIMIT 50;
