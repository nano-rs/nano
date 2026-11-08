-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-3514 (ported to clickhouse/dev as NAN-4930; main 341): marketplace sync
-- must re-parse when the sync CODE changes.
--
-- Enrichment marketplace sync skipped a repository whose HEAD commit equalled
-- `last_sync_commit`. That keys only on repository content: when sync learns
-- to record a new manifest field, repos at an unchanged commit never get it.
-- Sync now records the version of its parse/record logic
-- (`SYNC_SCHEMA_VERSION` in nanosiem-core/src/marketplace/sync_service.rs)
-- next to the commit, and a stored version that differs from the running one
-- forces a full sync.
--
-- Existing rows default to 0 ("synced by code that did not record a
-- version"), so every repository re-syncs once after this lands.
--
-- Additive and idempotent. Single-tenant: main's managed-owner (shared lake)
-- window is dropped.
DO $sync_schema_version$
BEGIN
    IF to_regclass('public.enrichment_marketplace_repos') IS NULL THEN
        RETURN;
    END IF;
    ALTER TABLE public.enrichment_marketplace_repos
        ADD COLUMN IF NOT EXISTS last_sync_schema_version INTEGER NOT NULL DEFAULT 0;
END
$sync_schema_version$;
