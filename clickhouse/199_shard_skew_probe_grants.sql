-- NAN-5342: SIEM Health shard-skew probe. The admin client fans out with
-- cluster(...); remote shards answer as the remote_servers user (Compose /
-- role-split: this runtime user), so it needs these column-scoped reads of
-- node-local system log tables on every node. No event table is involved.
-- users.d XML users carry the same grants (clickhouse/users.d/nanosiem-users.xml);
-- this migration reconciles SQL-created runtime users on existing installs.
-- metric_log (CH 26.x) keeps its values in the `metrics` Map behind ALIAS
-- columns; the initiator rewrites the aliases to metrics['...'] before the
-- query reaches a remote shard, so `metrics` is granted too (server counters).
GRANT{grant_on_cluster} SELECT(event_date, rows, part_name) ON system.part_log TO {clickhouse_runtime_user};
GRANT{grant_on_cluster} SELECT(event_date, event_time, metrics, CurrentMetric_BackgroundMergesAndMutationsPoolTask, CurrentMetric_BackgroundMergesAndMutationsPoolSize) ON system.metric_log TO {clickhouse_runtime_user};
GRANT{grant_on_cluster} SELECT(event_date, event_time, metric, value) ON system.asynchronous_metric_log TO {clickhouse_runtime_user};
GRANT{grant_on_cluster} SELECT(database, type) ON system.replication_queue TO {clickhouse_runtime_user};
-- Pre-existing XML grants the probe also reads through, restated so SQL-created
-- runtime users get them too.
GRANT{grant_on_cluster} SELECT(event_type, event_time, database, table) ON system.part_log TO {clickhouse_runtime_user};
GRANT{grant_on_cluster} SELECT(bytes_on_disk, rows, data_uncompressed_bytes, partition, database, table, active) ON system.parts TO {clickhouse_runtime_user};
