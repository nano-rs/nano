-- Migration: Link scheduled_jobs to lookup_tables_registry via lookup_table_name
-- This enables managing ingestion config as a child of a lookup table.

-- Step 1: Add the column (nullable initially)
ALTER TABLE scheduled_jobs ADD COLUMN IF NOT EXISTS lookup_table_name VARCHAR(255);

-- Step 2: Backfill from destination_config->>'table_name'
UPDATE scheduled_jobs
SET lookup_table_name = destination_config->>'table_name'
WHERE lookup_table_name IS NULL
  AND destination_config->>'table_name' IS NOT NULL;

-- Step 3: Delete orphaned jobs whose table no longer exists in the registry
DELETE FROM scheduled_jobs
WHERE lookup_table_name IS NOT NULL
  AND lookup_table_name NOT IN (SELECT name FROM lookup_tables_registry);

-- Step 3b: Delete jobs that couldn't be backfilled (no table_name in destination_config)
DELETE FROM scheduled_jobs
WHERE lookup_table_name IS NULL;

-- Step 4: Set NOT NULL (all remaining rows are guaranteed to have a value)
ALTER TABLE scheduled_jobs ALTER COLUMN lookup_table_name SET NOT NULL;

-- Step 5: Add unique index (one job per lookup table)
CREATE UNIQUE INDEX IF NOT EXISTS idx_scheduled_jobs_lookup_table_name
ON scheduled_jobs (lookup_table_name);

-- Step 6: Add FK to lookup_tables_registry — cascade delete removes the job when table is dropped
ALTER TABLE scheduled_jobs
ADD CONSTRAINT fk_scheduled_jobs_lookup_table
FOREIGN KEY (lookup_table_name) REFERENCES lookup_tables_registry(name) ON DELETE CASCADE;
