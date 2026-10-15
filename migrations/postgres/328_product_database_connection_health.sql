-- NAN-2407: one fresh capacity row per product database endpoint for collectors.
-- Narrow roles cannot see other sessions' backend_type. Count every activity
-- row rather than silently undercounting; this is a conservative cap alarm.
-- These aggregates are already visible to every login. No elevated statistics
-- privilege, query text, or other tenants' identities are exposed.
CREATE OR REPLACE FUNCTION lake_product_database_health_read()
RETURNS TABLE (
    stage text,
    producer text,
    database text,
    connections bigint,
    database_connections bigint,
    max_connections bigint,
    reserved_connections bigint,
    warning boolean,
    observed_at timestamptz
)
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog
AS $$
    SELECT 'product_database'::text, 'postgres'::text, current_database()::text,
           count(*)::bigint,
           count(*) FILTER (WHERE datname = current_database())::bigint,
           current_setting('max_connections')::bigint,
           current_setting('superuser_reserved_connections')::bigint,
           count(*) * 5 >= current_setting('max_connections')::bigint * 4,
           statement_timestamp()
    FROM pg_catalog.pg_stat_activity
$$;
GRANT EXECUTE ON FUNCTION lake_product_database_health_read() TO PUBLIC;
