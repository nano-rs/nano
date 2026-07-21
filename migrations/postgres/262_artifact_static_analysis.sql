-- NAN-1982: opaque static-analysis passthrough on artifacts.
--
-- Adds a nullable `static_analysis` jsonb column so tool findings (structured
-- static analysis that populates the Artifacts inspector) persist alongside the
-- report. This is an ADDITIVE, OPAQUE passthrough — the store does not model its
-- inner shape; the application binds and returns it verbatim (Option<Value>).
--
-- IMPORTANT (open-core): like 261, this is a CORE migration and runs on every
-- edition. Additive and idempotent (ADD COLUMN IF NOT EXISTS), safe to re-run.

ALTER TABLE public.artifacts ADD COLUMN IF NOT EXISTS static_analysis jsonb;
