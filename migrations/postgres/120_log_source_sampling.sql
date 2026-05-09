ALTER TABLE log_sources
  ADD COLUMN sampling_ratio DOUBLE PRECISION,
  ADD COLUMN sampling_exclude_condition TEXT;

COMMENT ON COLUMN log_sources.sampling_ratio IS 'Sample ratio 0.0-1.0 (e.g., 0.1 = keep 10%). NULL = no sampling (keep all).';
COMMENT ON COLUMN log_sources.sampling_exclude_condition IS 'VRL condition for events that are NEVER sampled (e.g., .action != "allow"). NULL = no exclusions.';
