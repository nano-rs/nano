-- Add MITRE-declared data sources to mitre_techniques.
--
-- The STIX bundle declares required data sources per technique via
-- `x_mitre_data_sources`. We persist them as a TEXT[] of human-readable
-- labels (e.g. "Process: Process Creation", "Network Traffic: Flow")
-- so the coverage API can derive per-technique data-source connectedness.
--
-- The mapping from these labels to nanosiem source_type identifiers lives
-- in `nanosiem_core::mitre::data_sources` (Rust) — kept out of the DB so
-- it can evolve without a migration.

ALTER TABLE mitre_techniques
    ADD COLUMN IF NOT EXISTS data_sources TEXT[] NOT NULL DEFAULT '{}'::TEXT[];

COMMENT ON COLUMN mitre_techniques.data_sources IS
    'MITRE-declared required data sources for this technique (verbatim x_mitre_data_sources strings). Populated by mitre sync.';
