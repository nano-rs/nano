-- NAN-3499: a lean finding is fully delivered when the detect[T] drain
-- acknowledges it, so `published_at` must say so.
--
-- `published_at` is the composite "every component delivered" stamp (291).
-- Gen1 sets it only after risk, Iceberg event AND serving generation all
-- acknowledge. A lean tenant has no serving generation: the detect drain
-- commits each finding in one signed part-log `Add` and acknowledges BOTH the
-- risk and the event component with the same `parts:<seq>:<entry sha256>`
-- marker in one statement. That part-log head is the lean serving state, so
-- the lean acknowledgement is complete. Before this migration it never set
-- `published_at`, so delivered lean findings looked pending forever (b12e5ee2
-- 2026-10-07: 56 rows acknowledged ~1 s after creation, published_at NULL),
-- and the published_at-keyed retention never removed them.
--
-- Gen1 semantics are unchanged: gen1 component publishers never write a
-- `parts:` snapshot id, and never write the same id to both components.
--
-- r30 fix-forward: this body first shipped as 344. Its backfill UPDATE needs
-- privileges on `detection_finding_lake_outbox`, which an activated
-- enterprise_shared database moved to the managed data owner (9000084), so
-- the migrator was refused there. 344 is retired (removed, not edited: a
-- database that already applied it keeps its row, which the open migrator's
-- ignore_missing tolerates, and this file then re-applies the same function
-- and finds nothing left to backfill). The trigger function stays owned by
-- the migrator; the backfill runs inside the 9000140 managed-owner bootstrap
-- window when one exists, as 341 does; open and dedicated installs update
-- directly.

CREATE OR REPLACE FUNCTION enforce_detection_lake_composite_ack()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.risk_published_at IS NOT NULL
       AND NEW.event_published_at IS NOT NULL
       AND NEW.generation_published_at IS NOT NULL THEN
        NEW.published_at := COALESCE(NEW.published_at, NOW());
        NEW.published_snapshot_id := NEW.serving_generation_id;
    ELSIF NEW.risk_published_at IS NOT NULL
       AND NEW.event_published_at IS NOT NULL
       AND NEW.event_snapshot_id LIKE 'parts:%'
       AND NEW.risk_snapshot_id = NEW.event_snapshot_id THEN
        -- Lean: one signed part-log head carries both components.
        NEW.published_at := COALESCE(NEW.published_at, NOW());
        NEW.published_snapshot_id := NEW.event_snapshot_id;
    ELSE
        NEW.published_at := NULL;
        NEW.published_snapshot_id := NULL;
    END IF;
    RETURN NEW;
END;
$$;

-- Rows the lean drain acknowledged before this migration: stamp them with
-- the time of their acknowledgement (both components were set together), so
-- retention counts from delivery, not from this migration.
DO $lean_finding_completion$
DECLARE
    owner_role NAME;
    owner_token INTEGER := 0;
BEGIN
    IF to_regproc('nano_shared.begin_managed_owner_bootstrap') IS NOT NULL THEN
        SELECT contract.owner_role INTO owner_role
          FROM nano_shared.rls_role_contract contract WHERE singleton AND enabled;
        IF owner_role IS NOT NULL THEN
            owner_token := nano_shared.begin_managed_owner_bootstrap(owner_role);
        END IF;
    END IF;
    UPDATE detection_finding_lake_outbox
    SET published_at = GREATEST(risk_published_at, event_published_at)
    WHERE published_at IS NULL
      AND risk_published_at IS NOT NULL
      AND event_published_at IS NOT NULL
      AND event_snapshot_id LIKE 'parts:%'
      AND risk_snapshot_id = event_snapshot_id;
    IF owner_role IS NOT NULL THEN
        PERFORM nano_shared.end_managed_owner_bootstrap(owner_role, owner_token);
    END IF;
END
$lean_finding_completion$;
