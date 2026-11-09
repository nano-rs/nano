-- NAN-5048: password-reset tokens are now stored as SHA-256 digests
-- (`hash_token`), exactly like refresh tokens, and looked up by digest.
--
-- Any token written by an earlier build is a PLAINTEXT value. It can no longer
-- be redeemed (redemption hashes the presented value, and a stored plaintext
-- would need a SHA-256 preimage), but it is still credential material at rest.
-- Raw and hashed values are both 64 hex characters and cannot be told apart
-- later, so clear every outstanding token once, at the upgrade boot, before the
-- new code serves. Reset tokens live one hour and were never delivered to a
-- user (no mailer is wired), so nothing legitimate is lost.
--
-- Forward-only and idempotent.
UPDATE public.users
   SET password_reset_token = NULL,
       password_reset_expires = NULL
 WHERE password_reset_token IS NOT NULL
    OR password_reset_expires IS NOT NULL;
