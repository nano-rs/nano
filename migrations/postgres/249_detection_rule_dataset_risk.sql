-- Allow detection rules over the derived `risk` dataset (NAN-1805, risk→CH P3).
--
-- NAN-1798 P2 (NAN-1804) made accumulated (decayed) entity risk queryable
-- from nPL as `dataset=risk` — one row per entity with score_24h/score_7d,
-- findings_*, distinct_rules_*, distinct_tactics_*, last_* columns. This
-- extends the migration-213 dataset CHECK so a SCHEDULED rule can run over
-- it, turning "risk notables" into ordinary detection rules
-- (e.g. `* | where score_24h > 500 or score_7d > 1000`).
--
-- Risk rules are SCHEDULED-ONLY, like spans/metrics: the real-time
-- materialized-view path reads FROM the logs table and rejects any non-logs
-- dataset (detection/materialized_view.rs).
--
-- Feedback-loop guard (enforced in code, not SQL): a rule with
-- dataset='risk' EMITS findings, and findings are the risk dataset's input —
-- so rule validation forces risk_score = 0 / no risk modifiers and rejects
-- `| risk` in the body, and the execution path zeroes any residual score
-- (detection/service/rules.rs + alerts.rs).
ALTER TABLE detection_rules
    DROP CONSTRAINT IF EXISTS detection_rules_dataset_check;

ALTER TABLE detection_rules
    ADD CONSTRAINT detection_rules_dataset_check
        CHECK (dataset IS NULL OR dataset IN ('logs', 'spans', 'metrics', 'risk'));

COMMENT ON COLUMN detection_rules.dataset IS 'Query dataset: NULL/logs (default), spans, metrics (NAN-1561), or risk (NAN-1805 — accumulated decayed entity risk). Non-logs datasets are scheduled-only (rejected by the real-time materialized-view path). Risk rules are forced to risk_score = 0 (feedback-loop guard).';
