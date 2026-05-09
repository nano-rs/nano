-- Remove settings/ingestion/data view permissions from ReadOnly role
-- ReadOnly users are analysts who view security data (search, alerts, dashboards)
-- They should not see configuration pages for ingestion, enrichments, or data management

DELETE FROM role_permissions
WHERE role_id = '00000000-0000-0000-0000-000000000003'  -- ReadOnly role
  AND permission_id IN (
    -- Settings
    'enrichments:view',
    -- Ingestion
    'log_sources:view',
    'source_configs:view',
    'credentials:view',
    -- Data
    'parsers:view',
    'lookup:view'
  );
