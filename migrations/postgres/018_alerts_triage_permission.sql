-- Add alerts:triage permission to RBAC system
-- This permission controls access to the AI Alert Triage feature

-- Insert the new permission into the permissions table
INSERT INTO permissions (id, name, description, category)
VALUES ('alerts:triage', 'Triage Alerts', 'Initiate AI-powered alert triage and analysis', 'alerts')
ON CONFLICT (id) DO NOTHING;

-- Grant the permission to the Admin role (assuming role_id for Admin)
-- The Admin role should have all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'alerts:triage'
FROM roles r
WHERE r.name = 'Admin'
ON CONFLICT DO NOTHING;

-- Grant the permission to the Analyst role (if exists)
-- Analysts should be able to triage alerts
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'alerts:triage'
FROM roles r
WHERE r.name = 'Analyst'
ON CONFLICT DO NOTHING;

-- Grant the permission to the SOC Analyst role (if exists)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'alerts:triage'
FROM roles r
WHERE r.name = 'SOC Analyst'
ON CONFLICT DO NOTHING;
