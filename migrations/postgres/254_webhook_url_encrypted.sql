-- F-39: encrypt the webhook destination URL at rest.
--
-- For a Slack / Teams incoming webhook the URL IS the bearer credential (anyone
-- who holds it can post into the channel), yet `webhooks.url` stored it in
-- cleartext and the API echoed it back in every WebhookResponse. This migration
-- adds an encrypted column (AES-256-GCM via the app's EncryptionService, same
-- envelope as headers_encrypted / secret_encrypted) plus a non-secret display
-- host label so the UI can still show *where* a channel points without leaking
-- the full secret URL.
--
-- The legacy plaintext `url` column is intentionally KEPT for now as a rollback
-- seam (an older binary can still read it); the application stops RETURNING it,
-- writes `url_encrypted` on create/update, and lazy-encrypts existing plaintext
-- rows on their next delivery/read. A follow-up migration can drop `url` once
-- the rollback window closes. No in-migration backfill: the encryption key lives
-- in the application, not the database.

-- Encrypted destination URL: JSON {"ciphertext":"...","nonce":"..."} bytes, the
-- same on-disk shape as headers_encrypted / secret_encrypted.
ALTER TABLE webhooks
    ADD COLUMN IF NOT EXISTS url_encrypted BYTEA;

-- Non-secret host label parsed from the URL (e.g. `hooks.slack.com`) for UI
-- display. Safe to return to API consumers; the path/token of a Slack/Teams
-- webhook URL — the actual secret — is never stored here.
ALTER TABLE webhooks
    ADD COLUMN IF NOT EXISTS url_host TEXT;
