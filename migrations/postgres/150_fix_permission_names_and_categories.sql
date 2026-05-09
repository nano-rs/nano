-- Fix permissions that were seeded with raw IDs as display names,
-- and correct category assignments for repository permissions.
-- NAN-351 follow-up: permission data quality cleanup

-- =====================================================
-- Fix display names (name column = raw ID instead of human-readable)
-- =====================================================

-- Cases
UPDATE public.permissions SET name = 'Assign Cases' WHERE id = 'cases:assign' AND name = 'cases:assign';
UPDATE public.permissions SET name = 'Close Cases' WHERE id = 'cases:close' AND name = 'cases:close';
UPDATE public.permissions SET name = 'Create Cases' WHERE id = 'cases:create' AND name = 'cases:create';
UPDATE public.permissions SET name = 'Delete Cases' WHERE id = 'cases:delete' AND name = 'cases:delete';
UPDATE public.permissions SET name = 'Edit Cases' WHERE id = 'cases:edit' AND name = 'cases:edit';
UPDATE public.permissions SET name = 'View Cases' WHERE id = 'cases:view' AND name = 'cases:view';

-- Detections
UPDATE public.permissions SET name = 'Export Detections' WHERE id = 'detections:export' AND name = 'detections:export';

-- Search
UPDATE public.permissions SET name = 'Raw SQL Access' WHERE id = 'search:sql' AND name = 'search:sql';

-- Sessions
UPDATE public.permissions SET name = 'Manage Sessions' WHERE id = 'sessions:admin' AND name = 'sessions:admin';

-- GDPR
UPDATE public.permissions SET name = 'Anonymize Data' WHERE id = 'gdpr:anonymize' AND name = 'gdpr:anonymize';

-- Notifications
UPDATE public.permissions SET name = 'View Notifications' WHERE id = 'notifications:view' AND name = 'notifications:view';
UPDATE public.permissions SET name = 'Manage Notifications' WHERE id = 'notifications:manage' AND name = 'notifications:manage';

-- Settings (sub-features seeded with raw IDs)
UPDATE public.permissions SET name = 'Agent Model Settings' WHERE id = 'settings:agent_models' AND name = 'settings:agent_models';
UPDATE public.permissions SET name = 'AI Provider Settings' WHERE id = 'settings:ai_providers' AND name = 'settings:ai_providers';

-- =====================================================
-- Fix category assignments
-- rule_repositories should be their own category, not 'detection'
-- parser_repositories should be their own category, not 'log_sources'
-- =====================================================

UPDATE public.permissions SET category = 'rule_repositories'
WHERE id LIKE 'rule_repositories:%' AND category = 'detection';

UPDATE public.permissions SET category = 'parser_repositories'
WHERE id LIKE 'parser_repositories:%' AND category = 'log_sources';

-- =====================================================
-- Remove dead permissions
-- These exist in the DB but are never enforced by any handler:
-- - detections:enable — replaced by Paused mode (detections:promote)
-- - case_settings:* — handlers use settings:view / settings:system
-- =====================================================

DELETE FROM public.role_permissions WHERE permission_id IN (
    'detections:enable',
    'case_settings:view',
    'case_settings:edit'
);

DELETE FROM public.permissions WHERE id IN (
    'detections:enable',
    'case_settings:view',
    'case_settings:edit'
);
