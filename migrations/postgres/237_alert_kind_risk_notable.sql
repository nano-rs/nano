-- NAN-1792: allow 'risk_notable' on the unified alert spine.
--
-- A risk notable is raised by the enterprise RiskNotableScheduler when an
-- entity's accumulated decayed risk score crosses the configured threshold.
-- It rides the same alerts table as every other producer, discriminated by
-- kind = 'risk_notable' (rule_id NULL, source_id = '<entity_type>:<entity>').
--
-- The migration-212 CHECK enumerates allowed kinds, so extend it. Open-core
-- deployments never insert this kind (the scheduler is enterprise-only) but
-- share the schema; the widened CHECK is harmless there.
ALTER TABLE public.alerts DROP CONSTRAINT IF EXISTS alerts_kind_check;
ALTER TABLE public.alerts
    ADD CONSTRAINT alerts_kind_check
    CHECK (kind IN ('detection', 'metric_monitor', 'slo', 'synthetic', 'risk_notable'));
