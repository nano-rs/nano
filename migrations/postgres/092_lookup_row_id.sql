-- Add _row_id BIGSERIAL column to all existing lookup tables for stable row identification.
-- New lookup tables will include _row_id automatically via create_dynamic_table.
DO $$
DECLARE
    tbl RECORD;
BEGIN
    FOR tbl IN SELECT table_name FROM lookup_tables_registry LOOP
        EXECUTE format(
            'ALTER TABLE %I ADD COLUMN IF NOT EXISTS _row_id BIGSERIAL',
            tbl.table_name
        );
    END LOOP;
END;
$$;
