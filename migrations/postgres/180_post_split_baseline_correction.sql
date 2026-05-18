-- Post open-core-split baseline correction. Audit of 177's open-tier
-- re-seed surfaced four classes of drift on fresh deploys that legacy
-- tenants don't have, because the audit'd migrations were backfilled past
-- 175 and never executed on a fresh DB:
--
--   * 104's GDPR salt UPDATE is gone — `system_settings.gdpr_anonymization_salt`
--     is left NULL, and every anonymization request 500s with
--     `AnonymizationError::SaltNotConfigured`.
--   * 150's permission display-name UPDATEs are gone — Settings → Permissions
--     shows ~13 rows with raw IDs ("cases:assign" instead of "Assign Cases").
--   * 150's permission-category UPDATEs are gone — `rule_repositories:*`
--     groups under `detection`, `parser_repositories:*` under `log_sources`.
--   * 150's zombie-permission DELETEs are gone — `detections:enable`,
--     `case_settings:view`, `case_settings:edit` are re-introduced by 177
--     and `detections:enable` is even granted to Editor by 177:305 (no
--     handler enforces any of them).
--
-- Replays 104:44-46 and 150:9-66 idempotently. Legacy tenants who already
-- ran those migrations are unaffected — the UPDATE guards (`name = id`,
-- `category = 'detection'`, `salt IS NULL`) make this a no-op there.
--
-- Pairs with the open-core-split audit punch list. The next regen of the
-- 177 snapshot will re-open these gaps unless `tools/nan749_split_open_overlay.py`
-- is fixed to capture INSERT data — that fix is filed as a separate ticket.

-- =====================================================
-- GDPR salt (mirror 104:44-46)
-- =====================================================

UPDATE public.system_settings
SET gdpr_anonymization_salt = encode(gen_random_bytes(32), 'hex')
WHERE id = 'default' AND gdpr_anonymization_salt IS NULL;

-- =====================================================
-- Permission display names (mirror 150:9-35).
-- The `name = <raw id>` guard means legacy tenants that already have
-- human-readable names hit the no-op branch.
-- =====================================================

-- Cases
UPDATE public.permissions SET name = 'Assign Cases'   WHERE id = 'cases:assign' AND name = 'cases:assign';
UPDATE public.permissions SET name = 'Close Cases'    WHERE id = 'cases:close'  AND name = 'cases:close';
UPDATE public.permissions SET name = 'Create Cases'   WHERE id = 'cases:create' AND name = 'cases:create';
UPDATE public.permissions SET name = 'Delete Cases'   WHERE id = 'cases:delete' AND name = 'cases:delete';
UPDATE public.permissions SET name = 'Edit Cases'     WHERE id = 'cases:edit'   AND name = 'cases:edit';
UPDATE public.permissions SET name = 'View Cases'     WHERE id = 'cases:view'   AND name = 'cases:view';

-- Detections
UPDATE public.permissions SET name = 'Export Detections' WHERE id = 'detections:export' AND name = 'detections:export';

-- Search
UPDATE public.permissions SET name = 'Raw SQL Access' WHERE id = 'search:sql' AND name = 'search:sql';

-- Sessions
UPDATE public.permissions SET name = 'Manage Sessions' WHERE id = 'sessions:admin' AND name = 'sessions:admin';

-- GDPR
UPDATE public.permissions SET name = 'Anonymize Data' WHERE id = 'gdpr:anonymize' AND name = 'gdpr:anonymize';

-- Notifications
UPDATE public.permissions SET name = 'View Notifications'    WHERE id = 'notifications:view'   AND name = 'notifications:view';
UPDATE public.permissions SET name = 'Manage Notifications' WHERE id = 'notifications:manage' AND name = 'notifications:manage';

-- Settings sub-features
UPDATE public.permissions SET name = 'Agent Model Settings' WHERE id = 'settings:agent_models' AND name = 'settings:agent_models';
UPDATE public.permissions SET name = 'AI Provider Settings' WHERE id = 'settings:ai_providers' AND name = 'settings:ai_providers';

-- =====================================================
-- Permission categories (mirror 150:43-47)
-- =====================================================

UPDATE public.permissions SET category = 'rule_repositories'
WHERE id LIKE 'rule_repositories:%' AND category = 'detection';

UPDATE public.permissions SET category = 'parser_repositories'
WHERE id LIKE 'parser_repositories:%' AND category = 'log_sources';

-- =====================================================
-- Remove zombie permissions (mirror 150:56-66).
-- `detections:enable` was replaced by Paused mode (`detections:promote`).
-- `case_settings:*` handlers were never written — `settings:view` /
-- `settings:system` cover the surface. Drop role grants first so the FK
-- doesn't block the permissions DELETE.
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
