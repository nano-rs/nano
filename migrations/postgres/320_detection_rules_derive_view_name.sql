-- Security review 2026-11-08 (NAN-5018): the real-time view name is always
-- derived from the rule id (`mv_rt_detection_<id without hyphens>`). The API no
-- longer accepts it from clients, and DDL never reads the column. Normalise any
-- stored value that differs from the derived name (only a client-set value can),
-- so the column shown to users matches the view that actually exists.
--
-- Forward-only and idempotent: re-running touches no rows. Rules that are not
-- real-time keep NULL.
DO $$
DECLARE
    fixed integer;
BEGIN
    UPDATE detection_rules
    SET materialized_view_name = 'mv_rt_detection_' || replace(id::text, '-', '')
    WHERE materialized_view_name IS NOT NULL
      AND materialized_view_name <> 'mv_rt_detection_' || replace(id::text, '-', '');
    GET DIAGNOSTICS fixed = ROW_COUNT;
    IF fixed > 0 THEN
        RAISE NOTICE 'NAN-5018: normalised materialized_view_name on % detection rule(s)', fixed;
    END IF;
END
$$;
