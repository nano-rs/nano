-- NAN-2137: durable origin provenance for persistent analytics artifacts.
--
-- A source-scoped reader cannot safely inspect frozen aggregates or prose to
-- remove facts from a newly denied source. Producers instead persist the
-- normalized union of every contributing origin plus an explicit completeness
-- bit. Legacy rows default to '{}' + FALSE and therefore fail closed.
--
-- There is intentionally no backfill: source provenance cannot be reconstructed
-- from already-materialized statistics or generated health-report prose.

ALTER TABLE detection_rule_metrics
    ADD COLUMN source_types TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN source_types_complete BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT detection_rule_metrics_source_provenance_valid
        CHECK (
            NOT source_types_complete
            OR (
                cardinality(source_types) > 0
                AND NOT (source_types @> ARRAY['__nano:unresolved_source__']::TEXT[])
            )
        );

ALTER TABLE detection_rule_baselines
    ADD COLUMN source_types TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN source_types_complete BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT detection_rule_baselines_source_provenance_valid
        CHECK (
            NOT source_types_complete
            OR (
                cardinality(source_types) > 0
                AND NOT (source_types @> ARRAY['__nano:unresolved_source__']::TEXT[])
            )
        );

ALTER TABLE siem_health_reports
    ADD COLUMN source_types TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN source_types_complete BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT siem_health_reports_source_provenance_valid
        CHECK (
            NOT source_types_complete
            OR (
                cardinality(source_types) > 0
                AND NOT (source_types @> ARRAY['__nano:unresolved_source__']::TEXT[])
            )
        );

COMMENT ON COLUMN detection_rule_metrics.source_types IS
    'Normalized union of origin source types contributing to this metrics snapshot';
COMMENT ON COLUMN detection_rule_baselines.source_types IS
    'Normalized union of origin source types contributing to this baseline';
COMMENT ON COLUMN siem_health_reports.source_types IS
    'Known origin source types contributing to the stored report payload';
