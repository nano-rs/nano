-- SPDX-License-Identifier: AGPL-3.0-or-later
-- ============================================================================
-- Migration 385: AI-search command allowlist (NAN-5437)
-- ============================================================================
-- Searches written by an AI (pivt, meloD tool loops, the nano MCP, Desktop
-- agents) may not use nPL commands that reach outside nano or write
-- (`inputlookup url=...`, `ai`, `output`). This column lists the ones an
-- administrator allows for AI searches anyway. Empty (the default) = none.
-- Human searches are not affected.
--
-- Forward-only, idempotent, no data backfill.
-- ============================================================================

ALTER TABLE system_settings
  ADD COLUMN IF NOT EXISTS search_ai_allowed_commands text[] NOT NULL DEFAULT '{}';
