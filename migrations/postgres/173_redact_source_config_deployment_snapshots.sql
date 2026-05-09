-- NAN-690: scrub historic secrets from deployment snapshots
--
-- Two parallel tables persisted the fully-rendered Vector TOML, which inlined
-- Kafka SASL passwords, AWS S3 secret_access_key + session_token (lifted from
-- decrypted cloud_credentials), and Splunk HEC valid_tokens:
--
--   * source_configuration_deployments.config_snapshot
--     — returned by GET /api/source-configurations/{id}/deployments,
--       gated only on `source_configs:view`.
--   * log_source_deployments.config_snapshot
--     — returned by GET /api/log-sources/{id}/deployments,
--       gated only on `log_sources:view`.
--
-- Either endpoint bypassed the AES-256-GCM encryption boundary on
-- cloud_credentials and, for HEC, preserved every rotated token forever.
--
-- The application now writes redacted snapshots going forward (see
-- `redact_config_snapshot` in nanosiem-core/src/parsers/vector_config/redaction.rs).
-- This migration scrubs every existing row across both tables so the historic
-- exposure window closes.
--
-- Replacement strategy: nested regexp_replace with the explicit `gn` flags
-- (g = replace all matches, n = make ^/$ match per-line) so we only consume
-- one TOML key at a time and preserve the rest of the document. Scoped via
-- a `~` prefilter in the WHERE clause so untouched rows (e.g. GCP-only
-- deployments) aren't dirtied. Idempotent — re-running on already-redacted
-- output produces the same string.
--
-- HEC operators MUST treat any historic `valid_tokens` value as compromised
-- and rotate; this migration only removes future readability of the snapshot
-- column, not the prior exposure of those tokens.
--
-- Single statement per table is fine here: deployment-history rows are
-- bounded by source-config / log-source count × deploy events, which is
-- small enough on every realistic install to scrub in one transaction.

UPDATE public.source_configuration_deployments
SET config_snapshot = regexp_replace(
    regexp_replace(
        regexp_replace(
            regexp_replace(
                config_snapshot,
                '^([ \t]*)password[ \t]*=.*$',
                '\1password = "***REDACTED***"',
                'gn'
            ),
            '^([ \t]*)secret_access_key[ \t]*=.*$',
            '\1secret_access_key = "***REDACTED***"',
            'gn'
        ),
        '^([ \t]*)session_token[ \t]*=.*$',
        '\1session_token = "***REDACTED***"',
        'gn'
    ),
    '^([ \t]*)valid_tokens[ \t]*=.*$',
    '\1valid_tokens = ["***REDACTED***"]',
    'gn'
)
WHERE config_snapshot IS NOT NULL
  AND config_snapshot ~ '(?n)^[ \t]*(password|secret_access_key|session_token|valid_tokens)[ \t]*=';

UPDATE public.log_source_deployments
SET config_snapshot = regexp_replace(
    regexp_replace(
        regexp_replace(
            regexp_replace(
                config_snapshot,
                '^([ \t]*)password[ \t]*=.*$',
                '\1password = "***REDACTED***"',
                'gn'
            ),
            '^([ \t]*)secret_access_key[ \t]*=.*$',
            '\1secret_access_key = "***REDACTED***"',
            'gn'
        ),
        '^([ \t]*)session_token[ \t]*=.*$',
        '\1session_token = "***REDACTED***"',
        'gn'
    ),
    '^([ \t]*)valid_tokens[ \t]*=.*$',
    '\1valid_tokens = ["***REDACTED***"]',
    'gn'
)
WHERE config_snapshot IS NOT NULL
  AND config_snapshot ~ '(?n)^[ \t]*(password|secret_access_key|session_token|valid_tokens)[ \t]*=';
