-- NAN-5217: who paused ingestion, why, and when.
--
-- `system_settings.ingestion_paused` (migration 097) is the cluster-wide
-- pause flag. Until NAN-5217 nothing enforced it and the status endpoint read
-- process memory, so the UI always said "Active". The flag is now enforced
-- (ClickHouse guard on the ingest users, the ingest edge's admission check and
-- the connector runner) and the status endpoint reads it from here.
--
-- These columns record where a pause came from so the UI can show it and an
-- automatic disk-pressure recovery never lifts an administrator's manual pause.
--
-- Forward-only and idempotent. A flag set by an older release (no provenance)
-- is cleared: it was never enforced, so enforcing it now would stop ingestion
-- on upgrade with no record of who paused it or why, and the disk-pressure
-- recovery lifts an automatic pause only once usage drops below the low
-- watermark. The monitor re-pauses on its next check if the disk really is at
-- the emergency level.

ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS ingestion_pause_source TEXT;
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS ingestion_pause_reason TEXT;
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS ingestion_paused_at TIMESTAMPTZ;
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS ingestion_paused_by UUID;

DO $$
BEGIN
    ALTER TABLE system_settings ADD CONSTRAINT system_settings_ingestion_pause_source_check
        CHECK (ingestion_pause_source IS NULL OR ingestion_pause_source IN ('disk_pressure', 'manual'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

UPDATE system_settings
   SET ingestion_paused = false
 WHERE ingestion_paused = true
   AND ingestion_pause_source IS NULL;
