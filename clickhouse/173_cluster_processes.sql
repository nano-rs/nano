-- NAN-2330: least-privilege cluster visibility for query progress, cancellation
-- preflight, and the cancelled-but-wedged watchdog.
--
-- clusterAllReplicas requires REMOTE, which is far broader than the runtime
-- app should hold. The admin migrator owns this narrow projection and evaluates
-- it as DEFINER. Runtime gets SELECT on the view, never REMOTE. The migrator
-- resolves the placeholder to system.processes on single-node or the cluster
-- fan-out source on clustered deployments.
CREATE OR REPLACE VIEW cluster_processes
DEFINER = {clickhouse_admin_user}
SQL SECURITY DEFINER
AS
SELECT
    query_id,
    user,
    elapsed,
    read_rows,
    total_rows_approx,
    is_cancelled,
    substring(normalizeQuery(query), 1, 200) AS query_snippet
FROM {system_processes_source};

-- Reconcile both paths for existing installs. Single-node cancellation uses the
-- system table directly; clustered reads use only the projection above.
GRANT{grant_on_cluster} SELECT ON system.processes TO {clickhouse_runtime_user};
GRANT{grant_on_cluster} SELECT ON cluster_processes TO {clickhouse_runtime_user};
