-- NAN-2212: seed `settings:ai_providers` / `settings:agent_models` and grant
-- them to the Admin role, so fresh installs regain the AI settings management
-- surfaces that NAN-2113 repointed onto these two capabilities.
--
-- Symptom this repairs: on a deployment installed after the open-core split,
-- upgrading to >= 0.1.686 silently removes the Providers, Models and Agent
-- Models tabs from Settings -> AI & pivt. Guidance / Usage / Monitoring remain
-- (they still authorize on the umbrella `settings:ai`), so the page reads as a
-- managed tenant with platform-locked AI rather than as a permission failure.
-- No error surfaces anywhere.
--
-- Why fresh installs lack the rows
-- --------------------------------
-- These two permissions are created only by 040_litellm_provider_config.sql
-- (lines 117-121). Since the split, a fresh DB does not execute pre-175
-- migration bodies at all: `OPEN_INIT_BASELINE_VERSION = 175`
-- (nanosiem-core/src/db/migrations.rs) applies the schema-only snapshot
-- postgres-open/000_open_init.sql and then backfills `_sqlx_migrations` rows
-- for 1..=175 without running them. 177_seed_open_baseline.sql re-seeds the
-- data those skipped bodies would have inserted, but deliberately carves 040
-- out ("litellm is no longer used", 177:24) — a premise that was wrong, since
-- the permissions outlived the litellm client.
--
-- 177:287 then grants Admin `SELECT id FROM permissions`, i.e. every row that
-- EXISTS. With the two rows absent, Admin is silently short two capabilities.
-- No wildcard rescues it: check_permission (nanosiem-api-lib/src/auth_context.rs)
-- is exact string matching and nothing seeds '*'.
--
-- Tenants installed before the split ran 040 for real, so they hold the rows
-- and 177's blanket grant covered them. That DB history is the only difference
-- between an affected and an unaffected deployment on identical images.
--
-- Why 180 didn't already catch it
-- -------------------------------
-- 180_post_split_baseline_correction.sql:65-66 replays 150's display-name
-- UPDATEs for these exact two permission ids, but never replays 040's INSERT
-- or its grant. `UPDATE ... WHERE id = '...'` is a silent no-op when the row is
-- absent, so the repair migration passed straight over the hole it was written
-- to find.
--
-- Names are inserted in their post-150 form ('AI Provider Settings',
-- 'Agent Model Settings') so 150's and 180's rename UPDATEs stay no-ops here
-- and this migration does not reintroduce the raw-id display names.

-- =====================================================
-- Permission rows (mirror 040:117-121, post-150 names)
-- =====================================================

INSERT INTO public.permissions (id, name, description, category) VALUES
    ('settings:ai_providers', 'AI Provider Settings', 'Manage AI provider credentials',        'settings'),
    ('settings:agent_models', 'Agent Model Settings', 'Configure per-agent model assignments', 'settings')
ON CONFLICT (id) DO NOTHING;

-- =====================================================
-- Grant to the Admin role
-- =====================================================
-- Deliberately NOT a copy of 040:123-127, which grants `WHERE r.name = 'admin'`
-- while the role is seeded as 'Admin' (001:3365, 177:264). Postgres `=` on text
-- is case-sensitive, so that grant has never fired on any install — legacy
-- tenants only received these capabilities via 177's blanket
-- `SELECT id FROM permissions`. Matching on the seeded id is the durable form.
--
-- The `is_system AND lower(name) = 'admin'` arm is a fallback for tenants whose
-- Admin role carries a different id: 001 seeds roles with `ON CONFLICT (name)
-- DO NOTHING`, so a pre-existing row named 'Admin' would have kept its own id.
-- `is_system` keeps a customer-created role merely *named* "admin" out of it —
-- these are management capabilities and must not be granted by name collision.
--
-- Scope note: intentionally granted to Admin only. `settings:ai` is held by
-- other principals (notably demo users, as a read-only meloD availability
-- probe — NAN-1198), and widening from it would hand those principals
-- provider-credential and model-catalog write authority, undoing NAN-2113.

INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r
CROSS JOIN (VALUES
    ('settings:ai_providers'),
    ('settings:agent_models')
) AS p(id)
WHERE r.id = '00000000-0000-0000-0000-000000000001'::uuid
   OR (r.is_system AND lower(r.name) = 'admin')
ON CONFLICT DO NOTHING;

-- Legacy tenants already hold both rows and both grants, so every statement
-- above is a no-op there.
--
-- Operational note: permissions are carried in the session token
-- (nanosiem-core/src/auth/types.rs, Claims::has_permission), so an affected
-- admin must re-authenticate before the restored tabs appear. Running this
-- migration alone will not refresh a live session.
