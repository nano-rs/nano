-- NAN-5490: system.disks columns the runtime user lacked. On a cluster the
-- SIEM Health disk table (health/disk_monitor.rs: name, path, total_space,
-- free_space, type) and disk pressure's physical-filesystem sample
-- (settings/disk_pressure.rs: name, total_space, free_space, keep_free_space,
-- type) run as clusterAllReplicas() from the admin identity. With staged
-- cluster auth every remote hop logs in as the runtime user, which had no
-- grant on `path` or `keep_free_space`, so the other replica's half failed
-- with ACCESS_DENIED on every read.
--
-- Also the Settings > Tiering catalog columns (NAN-5470) that the users.d XML
-- user received but SQL-created runtime users never did.
--
-- users.d XML users carry the same grants (clickhouse/users.d/nanosiem-users.xml);
-- this migration reconciles SQL-created runtime users on existing installs
-- (on users.d users the GRANT is refused read-only and the migrator moves on).
GRANT{grant_on_cluster} SELECT(path, keep_free_space) ON system.disks TO {clickhouse_runtime_user};
GRANT{grant_on_cluster} SELECT(object_storage_type) ON system.disks TO {clickhouse_runtime_user};
GRANT{grant_on_cluster} SELECT(volume_name, move_factor) ON system.storage_policies TO {clickhouse_runtime_user};
