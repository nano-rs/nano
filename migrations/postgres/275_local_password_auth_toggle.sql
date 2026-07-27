-- NAN-2181: tenant-level control over local email/password authentication, so
-- an organization can require its users to arrive through a configured OIDC
-- provider instead of local credentials.
--
-- Default TRUE preserves current behavior for every existing and new install.
-- Turning it off is an explicit administrative act, guarded server-side at the
-- local login endpoint — hiding the password UI is not the boundary.
--
-- This lives in the core series even though the setting is only *meaningful*
-- alongside SSO (enterprise). The gate itself sits in `AuthService::login`,
-- which is core, so the column must exist in every build. In an open-core
-- deployment there is no SSO surface to enable and no admin API to flip it, so
-- the flag stays TRUE and the code path is byte-identical to today.
--
-- Deliberately NOT covered by this flag: OIDC login, token refresh, logout,
-- active sessions, API keys, service authentication, and bootstrap/setup. None
-- of those are local password login, and treating them as such would lock a
-- tenant out of its own recovery paths.

ALTER TABLE system_settings
    ADD COLUMN IF NOT EXISTS local_password_auth_enabled BOOLEAN NOT NULL DEFAULT TRUE;

COMMENT ON COLUMN system_settings.local_password_auth_enabled IS
    'NAN-2181: when FALSE, POST /api/auth/login is rejected and users must sign in through an enabled OIDC provider. Enabling SSO-only mode requires at least one enabled provider, and the last enabled provider cannot be disabled or deleted while this is FALSE.';
