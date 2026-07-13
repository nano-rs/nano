-- Generic per-rule alert cooldown throttle (NAN-1805, risk→CH P3).
--
-- Motivation: the engine's window-dedup (detection_finding_emissions,
-- migration 201) keys grouped findings on the entity's newest-activity time
-- (`_last_seen`) or event content — so an entity that keeps producing NEW
-- activity re-alerts on every cycle. For most rules that's correct; for
-- accumulated-state rules (dataset='risk' notables) and other intentionally
-- noisy rules it is an alert storm. The retired RiskNotableScheduler
-- (NAN-1792) had a stronger guard: a TIME-based per-entity cooldown anchored
-- on a durable table, so a value flapping across the threshold inside the
-- window could not re-fire. This migration generalizes that guard to any
-- detection rule.
--
-- `alert_cooldown_minutes`: NULL / 0 = no cooldown (existing rules are
-- byte-identical in behavior). When > 0, the alert path suppresses an alert
-- for a (rule, entity) pair if an alert for the same pair fired within the
-- window. Enforced on the SCHEDULED alert paths (grouped + per-event) in
-- detection/service/alerts.rs.
ALTER TABLE detection_rules
    ADD COLUMN alert_cooldown_minutes INTEGER NULL;

ALTER TABLE detection_rules
    ADD CONSTRAINT detection_rules_alert_cooldown_check
        CHECK (alert_cooldown_minutes IS NULL OR
               (alert_cooldown_minutes >= 0 AND alert_cooldown_minutes <= 10080));

COMMENT ON COLUMN detection_rules.alert_cooldown_minutes IS
    'Per-(rule, entity) alert throttle in minutes (NAN-1805). NULL/0 = off. While set, an entity that alerted within the window is suppressed from re-alerting — time-based (anchored on detection_alert_entity_cooldowns), not edge-triggered, so threshold flapping cannot storm. Max 10080 (7 days).';

-- Durable per-(rule, entity) last-alert anchor — the cooldown authority.
-- Mirrors the retired scheduler's alerts-table anchor pattern
-- (AlertRepository::latest_alert_at_for_source, NAN-1563/NAN-1792): because
-- the anchor is persisted, it survives a jobs restart / leader failover — the
-- new leader sees the prior leader's last alert and respects the window
-- instead of re-firing. One row per (rule, entity), upserted when an alert
-- fires for that entity; rows for rules without a cooldown are never written.
--
-- The alerts table itself cannot serve as this anchor for detection alerts:
-- grouped alerts cover many entities per row and `source_id` carries only the
-- rule id, so per-entity anchoring needs its own keyed store.
CREATE TABLE IF NOT EXISTS detection_alert_entity_cooldowns (
    rule_id uuid NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    entity text NOT NULL,
    last_alert_at timestamp with time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, entity)
);

COMMENT ON TABLE detection_alert_entity_cooldowns IS
    'NAN-1805: durable per-(rule, entity) last-alert anchors for the alert_cooldown_minutes throttle. Time-based re-arm authority; survives restart/leader failover. Rows are upserted (one per pair) and opportunistically pruned (> 30 days stale) on write, so growth is bounded by live rule x entity cardinality.';
