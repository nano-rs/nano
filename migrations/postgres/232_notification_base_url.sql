-- NAN-1790: configurable external base URL for notification deep links.
--
-- Notification channels (Slack / Teams / PagerDuty) embed a deep link back to
-- the alert so a responder can jump straight into nano. Until now the only
-- source of the external base URL was the `NANOSIEM_HOSTNAME` env var (also used
-- by the OIDC issuer). That works for deployments that set it, but it is not
-- operator-configurable from the UI and is a bare host, not a full URL.
--
-- This adds an optional, admin-settable base URL on the single-row
-- `system_settings` table. Resolution order for deep links (see
-- WebhookService::resolve_base_url):
--   1. system_settings.notification_base_url (this column) when non-empty
--   2. NANOSIEM_HOSTNAME env var (as https://<host>)
--   3. no link (deep link omitted)
--
-- Stored as a full origin, e.g. 'https://nano.example.com' (no trailing slash;
-- normalized in the application layer). NULL = fall back to the env var.
ALTER TABLE system_settings
    ADD COLUMN IF NOT EXISTS notification_base_url TEXT;

COMMENT ON COLUMN system_settings.notification_base_url IS
    'External base origin for notification deep links (e.g. https://nano.example.com). NULL falls back to NANOSIEM_HOSTNAME.';
