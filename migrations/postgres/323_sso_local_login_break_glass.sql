-- NAN-5027: an account linked to SSO no longer keeps a usable local password.
--
-- On the FIRST SSO link of an existing row, the local password_hash is cleared
-- and every token/session issued before the link is revoked: a password chosen
-- by whoever created the row (for example a delegated users:create holder)
-- would otherwise be a local side door into an account the IdP may map to
-- privileged groups, bypassing the IdP and its MFA. Local password sign-in is
-- also refused for any SSO-linked account, which covers rows linked by an
-- earlier build that kept the hash.
--
-- `local_login_break_glass` is the audited exception: set by an administrator
-- (interactive session + settings:system) BEFORE the link, it keeps the local
-- password usable for recovery when the IdP is down — e.g. on the bootstrap
-- admin. Default FALSE; existing rows are not modified.
--
-- Forward-only, additive, idempotent.
ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS local_login_break_glass BOOLEAN NOT NULL DEFAULT FALSE;
