-- NAN-4995B: make detection lifecycle retries safe and preserve pause origin.
--
-- The legacy promote/demote endpoints accept a bodyless POST.  Record the
-- last unguarded transition so the repository can serialize requests and
-- suppress another unguarded transition during the compatibility dwell.
-- Guarded callers continue to use expected_mode compare-and-swap updates.
--
-- Paused rules historically always resumed to alerting.  Existing paused
-- rows came from that behavior, so backfill alerting as their origin while
-- all new pauses record the actual prior mode.

ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS paused_from_mode TEXT,
    ADD COLUMN IF NOT EXISTS legacy_lifecycle_transition_at TIMESTAMPTZ;

UPDATE detection_rules
SET paused_from_mode = 'alerting'
WHERE mode = 'paused'
  AND paused_from_mode IS NULL;

-- Keep the schema rolling-upgrade compatible. An older API process may still
-- execute its pre-315 `SET mode = 'paused'` / `SET mode = 'alerting'` SQL
-- after the migrator commits but before that process drains. The trigger
-- captures/restores/clears the origin for those writes so the invariant below
-- does not turn a rolling deploy into transient 500s or lose restoration mode.
CREATE OR REPLACE FUNCTION public.sync_detection_rule_paused_from_mode()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.mode = 'paused' THEN
        IF NEW.paused_from_mode IS NULL THEN
            IF TG_OP = 'UPDATE' AND OLD.mode IN ('staging', 'live', 'alerting') THEN
                NEW.paused_from_mode := OLD.mode;
            ELSE
                -- Directly creating a paused rule historically resumed to
                -- alerting; preserve that compatibility when no source exists.
                NEW.paused_from_mode := 'alerting';
            END IF;
        END IF;
    ELSIF TG_OP = 'UPDATE'
          AND OLD.mode = 'paused'
          AND OLD.paused_from_mode IN ('staging', 'live', 'alerting')
          AND NEW.mode = 'alerting'
          AND NEW.paused_from_mode = OLD.paused_from_mode THEN
        -- A pre-315 process resumes with only `SET mode = 'alerting'`.
        -- Recognize that exact legacy write shape and restore the captured
        -- origin instead. New writers clear paused_from_mode explicitly and
        -- therefore do not enter this compatibility branch.
        NEW.mode := OLD.paused_from_mode;
        NEW.paused_from_mode := NULL;
    ELSE
        NEW.paused_from_mode := NULL;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_detection_rules_pause_origin ON detection_rules;
CREATE TRIGGER trg_detection_rules_pause_origin
    BEFORE INSERT OR UPDATE ON detection_rules
    FOR EACH ROW
    EXECUTE FUNCTION public.sync_detection_rule_paused_from_mode();

ALTER TABLE detection_rules
    DROP CONSTRAINT IF EXISTS detection_rules_paused_from_mode_check;

ALTER TABLE detection_rules
    ADD CONSTRAINT detection_rules_paused_from_mode_check
    CHECK (
        (mode = 'paused' AND paused_from_mode IN ('staging', 'live', 'alerting'))
        OR (mode <> 'paused' AND paused_from_mode IS NULL)
    );

COMMENT ON COLUMN detection_rules.paused_from_mode IS
    'Lifecycle mode restored by resume; populated atomically when a rule enters paused mode.';

COMMENT ON COLUMN detection_rules.legacy_lifecycle_transition_at IS
    'Timestamp of the last unguarded promote/demote transition; repeated bodyless requests inside the compatibility dwell are replay-suppressed.';
