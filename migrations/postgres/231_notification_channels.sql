-- NAN-1790: native alert notification channels.
--
-- Generalizes the generic-webhook row into a typed notification CHANNEL:
-- type + config + secret + a provider-specific payload formatter, all riding
-- the same delivery spine (SSRF-pinned client, 3-attempt exponential-backoff
-- retries, delivery log, encrypted secret storage). Rather than a parallel
-- table, the existing `webhooks` table IS the channel store — every row gains a
-- `channel_type` and existing rows implicitly become `generic` channels, so no
-- configured webhook changes meaning and the `webhook_delivery_log` FK, the
-- `settings:webhooks` permission, and the CRUD endpoints all keep working.
--
-- channel_type values (validated in the application layer, like event_types, so
-- adding a future provider needs no migration):
--   'generic'   — signed JSON POST (the pre-existing behavior; unchanged bytes)
--   'slack'     — Slack incoming webhook, Block Kit payload
--   'teams'     — Microsoft Teams incoming webhook / workflow, Adaptive Card
--   'pagerduty' — PagerDuty Events API v2 (routing key in secret_encrypted)
--   'email'     — SMTP (formatter seam present; transport is a follow-up)
ALTER TABLE webhooks
    ADD COLUMN IF NOT EXISTS channel_type TEXT NOT NULL DEFAULT 'generic';

-- Non-secret, provider-specific configuration returned to the UI (e.g. SMTP
-- host/port/from for the email seam). Secrets (HMAC secret, PagerDuty routing
-- key, SMTP password) continue to live in the encrypted `secret_encrypted`
-- column — never here.
ALTER TABLE webhooks
    ADD COLUMN IF NOT EXISTS channel_config JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Optional detection-rule routing filter: fire this channel only for alerts
-- produced by these detection rules. NULL / empty = all rules (existing
-- behavior). Complements the existing event_types + severity_filter dimensions.
ALTER TABLE webhooks
    ADD COLUMN IF NOT EXISTS rule_filter UUID[];

COMMENT ON COLUMN webhooks.channel_type IS
    'Notification channel type: generic | slack | teams | pagerduty | email. Selects the payload formatter. Validated in the application layer.';
COMMENT ON COLUMN webhooks.channel_config IS
    'Non-secret provider config (JSON). Secrets stay in secret_encrypted.';
COMMENT ON COLUMN webhooks.rule_filter IS
    'Detection-rule routing filter: fire only for these rule ids. NULL/empty = all rules.';
