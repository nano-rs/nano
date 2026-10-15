-- Freeze every input used by asynchronous per-event alert side effects.
--
-- The original outbox stored only alert_id. Retrying after a rule edit then
-- rebuilt the finding, case, and webhook payload from the new rule version.
-- Finding IDs are deterministic by alert/event identity, so that correctly
-- failed as a conflicting replay and could strand the outbox row. The context
-- is nullable only so rows already queued by migration 305 can drain through
-- the explicit legacy fallback; all new rows populate it.

ALTER TABLE alert_post_create_outbox
    ADD COLUMN IF NOT EXISTS context JSONB;

COMMENT ON COLUMN alert_post_create_outbox.context IS
    'Immutable versioned rule, risk-weight, and case-routing inputs captured when the alert was created';
