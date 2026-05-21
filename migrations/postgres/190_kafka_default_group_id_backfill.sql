-- 190_kafka_default_group_id_backfill.sql
--
-- NAN-884 K-3: pin already-deployed Kafka source configs to the legacy
-- default consumer group_id ("nanosiem") so they keep their committed
-- broker-side offsets after the code change in this PR starts
-- auto-generating a per-config group_id from the source-config typeid.
--
-- Before NAN-931, `generate_kafka_source` defaulted `group_id` to the
-- literal "nanosiem" when the user didn't set one in connection_config.
-- After NAN-931, that branch auto-generates `nanosiem-<base32 typeid suffix>`
-- whenever `connection_config -> 'group_id'` is JSON-null / missing.
--
-- Without this backfill, every existing Kafka config with an implicit
-- group_id would switch to a new group on the next deploy. The new group
-- has no committed offsets, so it starts consuming from
-- `auto_offset_reset` — for `earliest` that means re-reading the full
-- topic backlog (potentially terabytes for production deployments).
--
-- Setting the key explicitly here makes the legacy behaviour the chosen
-- behaviour for these rows. New configs created after this migration
-- still get the unique auto-generated value because their JSON starts
-- without the key.

UPDATE source_configurations
   SET connection_config = jsonb_set(connection_config, '{group_id}', '"nanosiem"', true)
 WHERE config_type = 'kafka'
   AND NOT (connection_config ? 'group_id');
