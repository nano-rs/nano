-- NAN-5709: grant `rule_repositories:view` to the built-in ReadOnly role.
--
-- The Rules > Repositories rail item and route now gate on
-- `rule_repositories:view`, the permission every repository read endpoint
-- (`GET /api/rule-repositories`, `/{id}/rules`, `/{id}/folders`, ...) checks.
-- Before this, the rail and route used `detections:view`, so ReadOnly users
-- (and every custom role with only `detections:view`) opened a page whose own
-- list call answered 403.
--
-- Viewing is safe to grant read-only users: rule repositories are first-party
-- public content catalogs (migration 308), the repository record carries no
-- credentials (url, branch, sync status, counts), and a browsed repository
-- rule is catalog content, not a tenant object. Reading the LIVE detection a
-- repository rule is linked to still needs `detections:view`
-- (`GET /api/detection-rules/{id}/upstream-diff`, NAN-2103), and importing,
-- syncing and managing keep their own permissions.
--
-- ReadOnly is bound to the Everyone group, so this reaches every user. That is
-- the intent: the catalog is visible to anyone who can see detections. Editor
-- already holds it (177); re-asserted here so a tenant that lost the row is
-- consistent. Scoped API keys are deliberately NOT backfilled: a key's
-- permission list is an explicit grant by its creator.
--
-- Idempotent: ON CONFLICT DO NOTHING.

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, 'rule_repositories:view'
FROM (VALUES
    ('00000000-0000-0000-0000-000000000002'::uuid),  -- Editor
    ('00000000-0000-0000-0000-000000000003'::uuid)   -- ReadOnly
) AS r(role_id)
WHERE EXISTS (SELECT 1 FROM roles WHERE id = r.role_id)
  AND EXISTS (SELECT 1 FROM permissions WHERE id = 'rule_repositories:view')
ON CONFLICT DO NOTHING;
