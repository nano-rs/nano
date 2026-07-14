-- F-32 (red-team July 2026): forced-revocation watermark for access tokens.
--
-- Disabling a user (or a user changing their password) previously revoked
-- NOTHING for already-issued JWTs: the auth middleware trusted the token until
-- its natural expiry (default 900s). This column is stamped to NOW() on disable
-- and on password change; the middleware rejects any access token whose `iat`
-- predates it, so an outstanding (still-unexpired) token stops working
-- immediately rather than surviving up to 900s.
--
-- NULL (the default for every existing row) means "no forced revocation" — every
-- token is valid up to its own `exp`, i.e. today's behaviour is unchanged for
-- users who were never disabled and never changed their password.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS tokens_valid_from TIMESTAMPTZ DEFAULT NULL;
