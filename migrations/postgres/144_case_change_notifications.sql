-- Case change notifications via pg_notify
-- Fires on INSERT/UPDATE to cases table, sending a JSON payload
-- to the 'case_changes' channel. Catches all mutation paths:
-- handler, detection engine, bulk ops, merge.

CREATE OR REPLACE FUNCTION notify_case_change() RETURNS trigger AS $$
DECLARE
    payload jsonb;
    event_type text;
    group_ids uuid[];
BEGIN
    -- Determine event type
    IF TG_OP = 'INSERT' THEN
        event_type := 'created';
    ELSE
        event_type := 'updated';
    END IF;

    -- Collect shared group IDs for visibility filtering (cap at 50 to stay
    -- well under pg_notify's 8 KB payload limit)
    SELECT COALESCE(array_agg(g.group_id), '{}')
      INTO group_ids
      FROM (
          SELECT cg.group_id FROM case_groups cg
           WHERE cg.case_id = NEW.id
           LIMIT 50
      ) g;

    -- Build minimal payload for SSE visibility filtering
    payload := jsonb_build_object(
        'event',       event_type,
        'case_id',     NEW.id,
        'status',      NEW.status,
        'assigned_to', NEW.assigned_to,
        'visibility',  NEW.visibility,
        'created_by',  NEW.created_by,
        'group_ids',   to_jsonb(group_ids)
    );

    PERFORM pg_notify('case_changes', payload::text);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger on INSERT and UPDATE
CREATE TRIGGER trg_case_changes
    AFTER INSERT OR UPDATE ON cases
    FOR EACH ROW
    EXECUTE FUNCTION notify_case_change();
