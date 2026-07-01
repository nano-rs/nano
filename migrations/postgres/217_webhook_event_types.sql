-- NAN-1546: per-webhook event-type subscriptions.
--
-- Until now a webhook fired for exactly one thing (a detection alert), and only
-- if the (never-wired) detection→webhook call had been connected. As alerts now
-- carry a `kind` discriminator (migration 212: detection | metric_monitor | slo
-- | synthetic) and cases can also be forwarded to external systems, a webhook
-- needs to declare WHICH event streams it wants.
--
-- `event_types` is the subscription set. Categories:
--   'siem_alert' — alert record with kind = 'detection'
--   'obs_alert'  — alert record with kind in ('metric_monitor','slo','synthetic')
--   'case'       — case lifecycle event (created / status changed) [enterprise]
--
-- Existing rows backfill to {siem_alert, obs_alert}: that is exactly the
-- "all alerts, no cases" behavior a webhook implied before this column existed,
-- so no configured webhook changes meaning. New webhooks default the same way
-- (cases are opt-in). Membership is validated in the application layer
-- (CreateWebhookRequest / UpdateWebhookRequest) rather than a CHECK constraint,
-- so adding a future category needs no migration.
ALTER TABLE webhooks
    ADD COLUMN IF NOT EXISTS event_types TEXT[] NOT NULL
        DEFAULT ARRAY['siem_alert', 'obs_alert']::text[];

COMMENT ON COLUMN webhooks.event_types IS
    'Subscription set: which event streams fire this webhook. Values: siem_alert, obs_alert, case. Empty = all.';
