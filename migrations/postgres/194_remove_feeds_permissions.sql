-- NAN-1090: remove dead feeds:* permission
--
-- feeds:view / feeds:create / feeds:edit / feeds:delete were seeded in
-- 001_init_postgres.sql and 177_seed_open_baseline.sql for a planned
-- "feeds" feature that never shipped. No handler, no frontend, no
-- service layer ever enforced them — the lone orphan check on
-- /api/source-types was migrated to search:view in NAN-1089.
--
-- This migration removes the dead rows. Idempotent: re-running is safe.
-- Init/seed migrations stay untouched (sqlx checksum rule), so new
-- tenants will still insert feeds:* during bootstrap and this migration
-- will immediately remove them. Slightly wasteful but the only safe
-- path given the don't-modify-applied-migrations constraint.

DELETE FROM role_permissions WHERE permission_id LIKE 'feeds:%';
DELETE FROM permissions WHERE id LIKE 'feeds:%';
