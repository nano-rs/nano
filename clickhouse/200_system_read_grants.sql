-- NAN-5367: least-privilege system-table reads for the runtime user.
-- select_from_system_db_requires_grant is on (clickhouse/config.d/
-- access_control.xml; the official image already defaulted it on), so every
-- system table the runtime identity reads needs an explicit grant. These are
-- the reads that had none and failed with ACCESS_DENIED, directly or as the
-- remote half of an admin cluster()/clusterAllReplicas() probe (remote_servers
-- authenticate as this user). Column-scoped; no system.query_log `query`
-- column, no system.users.
-- users.d XML users carry the same grants (clickhouse/users.d/nanosiem-users.xml);
-- this migration reconciles SQL-created runtime users on existing installs.
GRANT{grant_on_cluster} SELECT(name) ON system.disks TO {clickhouse_runtime_user};
GRANT{grant_on_cluster} SELECT(policy_name, volume_priority, disks) ON system.storage_policies TO {clickhouse_runtime_user};
GRANT{grant_on_cluster} SELECT(disk_name) ON system.parts TO {clickhouse_runtime_user};
GRANT{grant_on_cluster} SELECT(database, table, data_files, error_count, last_exception) ON system.distribution_queue TO {clickhouse_runtime_user};
GRANT{grant_on_cluster} SELECT(name) ON system.settings_profiles TO {clickhouse_runtime_user};
GRANT{grant_on_cluster} SELECT(short_name, database, table, select_filter, is_restrictive, apply_to_all, apply_to_list, apply_to_except) ON system.row_policies TO {clickhouse_runtime_user};
GRANT{grant_on_cluster} SELECT(cluster, shard_num, replica_num, host_name, database_replica_name) ON system.clusters TO {clickhouse_runtime_user};
-- getMacro('replica') in the clustered refresh-activation probe.
GRANT{grant_on_cluster} SELECT(macro, substitution) ON system.macros TO {clickhouse_runtime_user};
