-- NAN-566: Sync `detection_rules.risk_score` column comment with the unified
-- severity-default table now exposed by `crate::detection::risk::default_score_for_severity`.
--
-- Migration 001 documented High=70 and Low=30, matching the legacy scheduled-path
-- defaults. The real-time materialized-view path used 75/25, and we have aligned
-- both code paths on the MV-path values. This migration brings the schema comment
-- in line with that decision so anyone reading the catalog gets the right values.

COMMENT ON COLUMN public.detection_rules.risk_score IS
    'Base risk score (0-100). If NULL, defaults based on severity: Critical=90, High=75, Medium=50, Low=25, Informational=10';
