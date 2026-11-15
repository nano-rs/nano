-- SPDX-License-Identifier: AGPL-3.0-or-later
-- ============================================================================
-- Migration 387: lookup URL allowlist managed in Settings (NAN-5443)
-- ============================================================================
-- Hosts that `inputlookup url=...` may fetch from, edited by administrators
-- in Settings -> Lookup URLs. The api, jobs and search processes merge this
-- list with the deployment list (INPUTLOOKUP_ALLOWED_DOMAINS) and re-read it
-- every 30 s. Empty (the default) adds nothing.
--
-- Forward-only, idempotent, no data backfill.
-- ============================================================================

ALTER TABLE system_settings
  ADD COLUMN IF NOT EXISTS inputlookup_allowed_domains text[] NOT NULL DEFAULT '{}';
