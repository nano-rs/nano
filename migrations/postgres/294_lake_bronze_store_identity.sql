-- NAN-2361: make a bronze object's durable identity include its assigned
-- object store. Object keys and version IDs are scoped to a bucket/store, so
-- they are not globally unique when one tenant is migrated between stores or
-- when an isolated validation store runs beside the tenant's active store.
--
-- Every statement here is re-runnable. A migration batch that fails partway
-- through (a lock timeout on a populated table, an interrupted deploy) would
-- otherwise abort on retry at the very first ALTER and need hand repair.
-- PostgreSQL has no IF NOT EXISTS for ADD CONSTRAINT / ADD PRIMARY KEY, so
-- those two are guarded by explicit catalogue checks rather than by swallowing
-- exceptions -- note that a second PRIMARY KEY raises invalid_table_definition
-- (42P16), not duplicate_object (42710), so a duplicate_object-only catch would
-- not have held anyway.

ALTER TABLE lake_bronze_object_publications
    ADD COLUMN IF NOT EXISTS bronze_store_id text;

-- NAN-2361 has not shipped yet, but development databases may already contain
-- rows written by migration 293. Preserve those rows under an explicit legacy
-- scope instead of guessing which object store they came from.
UPDATE lake_bronze_object_publications
SET bronze_store_id = 'legacy-unscoped'
WHERE bronze_store_id IS NULL;

ALTER TABLE lake_bronze_object_publications
    ALTER COLUMN bronze_store_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'lake_bronze_object_publications'::regclass
          AND conname = 'lake_bronze_store_id_canonical'
    ) THEN
        ALTER TABLE lake_bronze_object_publications
            ADD CONSTRAINT lake_bronze_store_id_canonical
                CHECK (bronze_store_id ~ '^[a-z0-9][a-z0-9._:/-]{0,255}$');
    END IF;
END
$$;

-- Swap the primary key onto the store-scoped identity. Skipped outright when the
-- key already covers exactly these four columns, so a re-run never drops and
-- rebuilds a key that is already correct.
DO $$
DECLARE
    desired text[] := ARRAY['tenant_id', 'bronze_store_id', 'object_key', 'version_id'];
    current_key text[];
BEGIN
    SELECT array_agg(attname ORDER BY ordinality)
    INTO current_key
    FROM pg_constraint
    JOIN unnest(conkey) WITH ORDINALITY AS key(attnum, ordinality) ON true
    JOIN pg_attribute ON pg_attribute.attrelid = conrelid
        AND pg_attribute.attnum = key.attnum
    WHERE conrelid = 'lake_bronze_object_publications'::regclass
      AND contype = 'p';

    IF current_key IS DISTINCT FROM desired THEN
        ALTER TABLE lake_bronze_object_publications
            DROP CONSTRAINT IF EXISTS lake_bronze_object_publications_pkey;
        ALTER TABLE lake_bronze_object_publications
            ADD PRIMARY KEY (tenant_id, bronze_store_id, object_key, version_id);
    END IF;
END
$$;

DROP INDEX IF EXISTS idx_lake_bronze_publications_pending;

CREATE INDEX IF NOT EXISTS idx_lake_bronze_publications_pending
    ON lake_bronze_object_publications
        (tenant_id, bronze_store_id, batch_sha256, object_key, version_id)
    WHERE status = 'pending';

COMMENT ON COLUMN lake_bronze_object_publications.bronze_store_id IS
    'Stable operator-assigned identity for the source object store; it must survive endpoint and credential rotation.';
