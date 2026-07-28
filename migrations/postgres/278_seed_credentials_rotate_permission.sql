-- NAN-2218: seed `credentials:rotate` and grant it to Admin, so fresh installs
-- regain cloud-credential rotation and rollback.
--
-- Same class as NAN-2212 (see 277), different permission and a different reason
-- for the gap.
--
-- Symptom this repairs: on a deployment installed after the open-core split,
-- `POST /api/credentials/{id}/rotate` and `.../rollback` return 403 for EVERY
-- principal, Admin included. The UI hides the controls (`Credentials.tsx`
-- gates `canRotate`), so nothing appears broken — the buttons are simply
-- absent, and a customer who believes they can rotate a leaked cloud
-- credential from the product cannot.
--
-- Why fresh installs lack the row
-- ------------------------------
-- `credentials:rotate` is created only by 165_cloud_credentials_versions.sql.
-- Version 165 <= OPEN_INIT_BASELINE_VERSION (175), so on a fresh DB its body
-- never executes — the snapshot is applied and `_sqlx_migrations` is backfilled
-- for 1..=175 without running them.
--
-- Unlike 040 (NAN-2212), 165 was not a deliberate carve-out: 177's catalogue
-- header enumerates its source migrations as "001, 007, 009, 018, 019, 026,
-- 028, 039, 047, 055, 071, 074, 090, 093, 099, 104, 128, 129, 149" and 165
-- appears in neither that list nor the carve-out list. It was simply missed.
-- 177's credentials block seeds only view/create/edit/delete.
--
-- 177:286 then grants Admin `SELECT id FROM permissions` — every row that
-- EXISTS — so with the row absent Admin is short one capability.
--
-- Why an admin cannot fix this without a migration
-- -----------------------------------------------
-- Three independent blocks, which is why this needs shipping rather than a
-- support note:
--   1. `/api/permissions` reads `SELECT * FROM permissions`, so the row is
--      absent from the Roles editor AND the API-key scope picker.
--   2. NAN-2121's hold-to-grant rule requires the caller to already HOLD any
--      permission it assigns; nobody holds this one, so even a hand-crafted
--      API call fails.
--   3. `role_permissions.permission_id` is FK'd to `permissions(id)`.
--
-- Name matches 165's exactly, so this is byte-equivalent to what a legacy
-- tenant already has.

INSERT INTO public.permissions (id, name, description, category) VALUES
    ('credentials:rotate', 'Rotate Credentials', 'Rotate or rollback the secret material on a cloud credential', 'credentials')
ON CONFLICT (id) DO NOTHING;

-- Admin only, mirroring 165's intent: rotation replaces secret material and
-- downstream source configs pick up the new secret on next deploy.
--
-- Granted by role id. The `is_system` arm covers a tenant whose Admin role
-- kept a non-seeded id (001 seeds roles `ON CONFLICT (name) DO NOTHING`, so a
-- pre-existing row named 'Admin' would have retained its own id), while
-- keeping a customer-created role merely *named* "admin" out of it.
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, 'credentials:rotate'
FROM public.roles r
WHERE r.id = '00000000-0000-0000-0000-000000000001'::uuid
   OR (r.is_system AND lower(r.name) = 'admin')
ON CONFLICT DO NOTHING;

-- Legacy tenants ran 165 for real and already hold both, so every statement
-- above is a no-op there.
--
-- Operational note: permissions are carried in the session token, so an
-- affected admin must re-authenticate before the rotate controls reappear.
