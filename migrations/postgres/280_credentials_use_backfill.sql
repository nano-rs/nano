-- NAN-2220: ship the `credentials:use` backfill that was the plan of record.
--
-- NAN-2125 added a `credentials:use` requirement to source-config create,
-- update, deploy and deploy_all. 270_credentials_use_permission.sql granted it
-- to the Admin and Editor role ids only, with the comment "Custom roles must
-- opt in to this runtime-secret capability".
--
-- That contradicts the recorded decision. NAN-2029-CODEX-HANDOFF.md:155-156,
-- marked "DECIDED (human, 2026-07-24)", specifies a predicate backfill derived
-- from `credentials:view` — noted there as reaching "EVERY role incl. custom" —
-- plus an `array_append` onto `api_keys.permissions`. Neither shipped, and no
-- release note documented the narrower behaviour. This migration closes that
-- gap; if the narrower stance is later preferred, amend the decision rather
-- than leaving the two out of step.
--
-- Why the gap breaks working deployments
-- --------------------------------------
-- The service re-checks against the SAVED row, not just the request:
-- `request.credential_id.or(existing.credential_id)`. So merely RENAMING a
-- source config whose stored row references a credential now demands
-- `credentials:use`. `deploy_all` preflights the whole set and fails the entire
-- batch on the first credentialed config. And 271 CREATES new
-- `source_configurations` rows carrying `credential_id` on the same upgrade,
-- enlarging the affected set.
--
-- The failure is loud (403 "Missing permission: credentials:use") but has no
-- automated remedy, and it halts ingestion automation.
--
-- Ordering note: this must run AFTER 279, which removes `credentials:view`
-- from ReadOnly. Deriving from `credentials:view` therefore does not hand
-- `credentials:use` to ReadOnly — consistent with 270's stated intent that
-- "viewing metadata must not confer the ability to decrypt or publish stored
-- credential material".

-- ---------------------------------------------------------------------------
-- Roles: every role that can already see credential metadata and could
-- therefore already manage credentialed source configs before NAN-2125.
-- ---------------------------------------------------------------------------

INSERT INTO public.role_permissions (role_id, permission_id)
SELECT DISTINCT rp.role_id, 'credentials:use'
FROM public.role_permissions rp
WHERE rp.permission_id = 'credentials:view'
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- API keys: `api_keys.permissions` is a plain text[] that NO migration has
-- ever written — the only api_keys statements in the whole tree are 001's DDL
-- and 272's trigger. Nothing re-derives a key's permissions from roles
-- (`AuthContext::from_api_key` clones the row verbatim), so a key that is not
-- rewritten here stays broken until a human edits it one at a time.
-- ---------------------------------------------------------------------------

UPDATE public.api_keys
SET permissions = array_append(permissions, 'credentials:use')
WHERE 'credentials:view' = ANY (permissions)
  AND NOT ('credentials:use' = ANY (permissions));

-- Applied to every matching key regardless of `enabled`/`expires_at`. A
-- permission on a disabled or expired key is inert — it cannot authenticate —
-- and scoping to active keys only would silently re-create this bug for any
-- key an operator later re-enables.
--
-- Idempotent in both halves: ON CONFLICT DO NOTHING on the role grants, and
-- the NOT (... = ANY ...) guard on the array update.
