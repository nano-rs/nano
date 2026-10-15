-- NAN-2361: a lake event is not fully published until every serving component
-- derived from it has crossed the same immutable generation boundary.
--
-- Detection Signals need three acknowledgements: the canonical OCSF event in
-- Iceberg, compact risk state, and the serving generation containing exact
-- sidecars/rollups. Platform audit events need the Iceberg event and serving
-- generation. The final legacy stamps are maintained only by database triggers
-- so a component publisher cannot acknowledge the composite handoff early.

ALTER TABLE detection_finding_lake_outbox
    ADD COLUMN IF NOT EXISTS risk_published_at timestamptz,
    ADD COLUMN IF NOT EXISTS risk_snapshot_id text,
    ADD COLUMN IF NOT EXISTS event_published_at timestamptz,
    ADD COLUMN IF NOT EXISTS event_snapshot_id text,
    ADD COLUMN IF NOT EXISTS generation_published_at timestamptz,
    ADD COLUMN IF NOT EXISTS serving_generation_id text;

-- Rows acknowledged by the original beta publisher only crossed the risk
-- boundary. Preserve that truthful component state and revoke the premature
-- composite acknowledgement.
UPDATE detection_finding_lake_outbox
SET risk_published_at = COALESCE(risk_published_at, published_at),
    risk_snapshot_id = COALESCE(risk_snapshot_id, published_snapshot_id),
    published_at = NULL,
    published_snapshot_id = NULL
WHERE published_at IS NOT NULL
  AND (
      event_published_at IS NULL
      OR generation_published_at IS NULL
      OR risk_published_at IS NULL
  );

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
    ELSE
        NEW.published_at := NULL;
        NEW.published_snapshot_id := NULL;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_detection_lake_composite_ack
    ON detection_finding_lake_outbox;
CREATE TRIGGER trg_detection_lake_composite_ack
BEFORE INSERT OR UPDATE ON detection_finding_lake_outbox
FOR EACH ROW
EXECUTE FUNCTION enforce_detection_lake_composite_ack();

DROP INDEX IF EXISTS idx_detection_finding_lake_outbox_pending;
CREATE INDEX idx_detection_finding_lake_outbox_pending
    ON detection_finding_lake_outbox (tenant_id, created_at, finding_id)
    WHERE published_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_detection_finding_lake_outbox_risk_pending
    ON detection_finding_lake_outbox (tenant_id, created_at, finding_id)
    WHERE risk_published_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_detection_finding_lake_outbox_event_pending
    ON detection_finding_lake_outbox (tenant_id, created_at, finding_id)
    WHERE event_published_at IS NULL;

ALTER TABLE platform_audit_events
    ADD COLUMN IF NOT EXISTS lake_event_published_at timestamptz,
    ADD COLUMN IF NOT EXISTS lake_event_snapshot_id text,
    ADD COLUMN IF NOT EXISTS lake_generation_published_at timestamptz,
    ADD COLUMN IF NOT EXISTS lake_serving_generation_id text;

-- Migration 290's beta path did not have a publisher that could truthfully set
-- lake_published_at, but clear any partial acknowledgement defensively.
UPDATE platform_audit_events
SET lake_event_published_at = COALESCE(lake_event_published_at, lake_published_at),
    lake_event_snapshot_id = COALESCE(lake_event_snapshot_id, lake_published_snapshot_id),
    lake_published_at = NULL,
    lake_published_snapshot_id = NULL
WHERE lake_published_at IS NOT NULL
  AND lake_generation_published_at IS NULL;

CREATE OR REPLACE FUNCTION enforce_audit_lake_composite_ack()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.ocsf_event IS NOT NULL
       AND NEW.lake_event_published_at IS NOT NULL
       AND NEW.lake_generation_published_at IS NOT NULL THEN
        NEW.lake_published_at := COALESCE(NEW.lake_published_at, NOW());
        NEW.lake_published_snapshot_id := NEW.lake_serving_generation_id;
    ELSE
        NEW.lake_published_at := NULL;
        NEW.lake_published_snapshot_id := NULL;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_lake_composite_ack ON platform_audit_events;
CREATE TRIGGER trg_audit_lake_composite_ack
BEFORE INSERT OR UPDATE ON platform_audit_events
FOR EACH ROW
EXECUTE FUNCTION enforce_audit_lake_composite_ack();

DROP INDEX IF EXISTS idx_platform_audit_events_lake_pending;
CREATE INDEX idx_platform_audit_events_lake_pending
    ON platform_audit_events (tenant_id, occurred_at, event_id)
    WHERE ocsf_event IS NOT NULL AND lake_published_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_platform_audit_events_lake_event_pending
    ON platform_audit_events (tenant_id, occurred_at, event_id)
    WHERE ocsf_event IS NOT NULL AND lake_event_published_at IS NULL;

COMMENT ON COLUMN detection_finding_lake_outbox.published_at IS
    'Composite acknowledgement set only after risk, Iceberg event, and serving generation publication all succeed.';
COMMENT ON COLUMN platform_audit_events.lake_published_at IS
    'Composite acknowledgement set only after Iceberg event and serving generation publication both succeed.';
