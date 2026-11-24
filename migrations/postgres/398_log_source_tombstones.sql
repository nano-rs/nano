-- NAN-5760: SIEM Health kept reporting deleted log sources.
--
-- The health report's per-source lists (active sources, silent sources,
-- field / enrichment coverage) are derived from ClickHouse `source_type`
-- values, not from the source registry. A deleted source's events stay in
-- `logs`, so for up to 48h after a delete it was listed as "silent" (data in
-- the prior 24h, none since) and dragged the ingestion score down.
--
-- A tombstone records the identity of a deleted log source that had a live
-- claim on its route keys: it was deployed (now or ever), or an ingest token
-- was bound to it. A never-deployed, never-token-bound draft leaves NO
-- tombstone, so creating and deleting a draft cannot hide anything (NAN-5760
-- review P1). The health reader derives the route keys in Rust, refuses
-- platform/reserved keys and keys another live source or routing rule claims,
-- and only sets a key aside when ClickHouse shows that source's events from
-- before the delete and none after it.
--
-- BEFORE DELETE, so `log_source_deployments` (ON DELETE CASCADE) and
-- `ingest_tokens.source_id` (ON DELETE SET NULL) still show the source's
-- history. Written in the delete's own transaction on EVERY delete path.
-- Tombstones older than 7 days are pruned by the same trigger: the health
-- windows are 48h, so an older tombstone can no longer affect any report.
--
-- Forward-only: a new table and two triggers. No backfill: deletes made
-- before this migration left no trace in PostgreSQL, and their data ages out
-- of the 48h health windows on its own.

-- Attaching a trigger takes SHARE ROW EXCLUSIVE on log_sources; never queue
-- behind a long deploy transaction during a rolling upgrade.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS public.log_source_tombstones (
    log_source_id UUID PRIMARY KEY,
    name          TEXT NOT NULL,
    match_values  TEXT[],
    deleted_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS log_source_tombstones_deleted_at
    ON public.log_source_tombstones (deleted_at);

CREATE OR REPLACE FUNCTION public.record_log_source_tombstone()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.deployed
       OR OLD.deployed_at IS NOT NULL
       OR EXISTS (
           SELECT 1 FROM public.log_source_deployments d
           WHERE d.log_source_id = OLD.id AND d.action = 'deploy' AND d.status = 'success'
       )
       OR EXISTS (
           SELECT 1 FROM public.ingest_tokens t WHERE t.source_id = OLD.id
       )
    THEN
        INSERT INTO public.log_source_tombstones (log_source_id, name, match_values, deleted_at)
        VALUES (OLD.id, OLD.name, OLD.match_values, now())
        ON CONFLICT (log_source_id) DO UPDATE
            SET name = EXCLUDED.name,
                match_values = EXCLUDED.match_values,
                deleted_at = EXCLUDED.deleted_at;
    END IF;
    RETURN OLD;
END;
$$;

CREATE OR REPLACE FUNCTION public.prune_log_source_tombstones()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM public.log_source_tombstones
    WHERE deleted_at < now() - INTERVAL '7 days';
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS log_sources_record_tombstone ON public.log_sources;
CREATE TRIGGER log_sources_record_tombstone
BEFORE DELETE ON public.log_sources
FOR EACH ROW EXECUTE FUNCTION public.record_log_source_tombstone();

DROP TRIGGER IF EXISTS log_sources_prune_tombstones ON public.log_sources;
CREATE TRIGGER log_sources_prune_tombstones
AFTER DELETE ON public.log_sources
FOR EACH STATEMENT EXECUTE FUNCTION public.prune_log_source_tombstones();
