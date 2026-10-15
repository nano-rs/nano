-- NAN-2875: lookup delete and replace purge rows with ALTER TABLE ... DELETE.
-- The runtime user needs this narrow grant on existing deployments as well as
-- fresh installs; without it both operations fail with Code 497 ACCESS_DENIED.
GRANT{grant_on_cluster} ALTER DELETE ON nanosiem.lookup_rows TO {clickhouse_runtime_user};
