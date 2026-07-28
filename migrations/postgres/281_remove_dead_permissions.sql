-- NAN-2226: drop five permissions that are seeded and grantable but enforced
-- nowhere, so the Roles editor and API-key scope picker stop advertising
-- authority that does nothing.
--
-- Each was verified to have zero enforcement: no `ensure_permission` /
-- `check_permission` call site, no `has_permission` literal, no constant
-- reference outside `nanosiem-core/src/auth/permissions.rs`, and no gate in
-- `nanosiem-web` or `nano-desktop`.
--
--   alerts:triage        — 018 granted it to roles named 'Analyst'/'SOC
--                          Analyst' that have never existed; no handler reads it.
--   parsers:delete       — leftovers from the `parsers` table dropped in 051.
--   parsers:deploy         Parser mutations actually gate on `parsers:edit`.
--   notifications:manage — notification handlers gate on `notifications:view`
--                          only.
--   settings:risk        — documented dead: NAN-2114 moved the risk-settings
--                          gate to `risk:configure`, and the handler's own
--                          comment records that settings:risk "is no longer
--                          enforced here".
--
-- The catalogue is the security contract an operator reads when building a
-- custom role: a permission that appears in the picker but gates nothing
-- invites an operator to believe they have restricted something they have not.
-- `settings:risk` is the sharp case — it was the advertised authority for risk
-- settings until NAN-2114, so a role built on it silently lost that authority
-- and a role denied it never actually had it withheld.
--
-- Grants are removed automatically: `role_permissions.permission_id` is FK'd to
-- `permissions(id)` ON DELETE CASCADE.
--
-- Follows 180's zombie-permission pattern (which removed `detections:enable`,
-- `case_settings:view`, `case_settings:edit` for the same reason).
--
-- Note on API keys: `api_keys.permissions` is an unconstrained text[], so any
-- key literally carrying one of these strings keeps it. That is harmless —
-- the strings were already inert — and rewriting customer key arrays to strip
-- a no-op is not worth the blast radius.

DELETE FROM public.permissions
WHERE id IN (
    'alerts:triage',
    'parsers:delete',
    'parsers:deploy',
    'notifications:manage',
    'settings:risk'
);

-- Idempotent: deleting absent rows affects zero rows.
