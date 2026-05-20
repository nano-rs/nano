-- NAN-883 / NAN-855: enforce single splunk_hec source configuration.
--
-- The `splunk_hec` OOTB Vector listener (config/vector/02-hec-source.toml,
-- :8088, shared ${VECTOR_AUTH_TOKEN}) is platform-managed. A user
-- splunk_hec source config is a routing profile over that shared listener,
-- not a new socket. Two of them would emit colliding `splunk_hec_route`
-- transforms (NAN-857, NAN-867).
--
-- Application-level enforcement lives in
-- `SourceConfigService::create` (`is_single_instance_driver`); this
-- migration adds the DB-level backstop so a check-then-act race between
-- two concurrent POSTs can't slip through.
--
-- NAN-855: also clear the vestigial connection_config fields
-- (`address`, `valid_tokens`, `permit_origin`, `tls`) on any existing
-- splunk_hec rows. Post-NAN-853 these are silently ignored at deploy
-- time, and the post-NAN-855 validator rejects them on the next update —
-- pre-clearing prevents a rename / description edit from blowing up on
-- legacy stored values. The OOTB seed row (047_source_configurations.sql,
-- id 30000000-0000-0000-0000-000000000006) is the typical case here.

-- Step 1: clear vestigial fields. `-` is the jsonb key-removal operator
-- and is a no-op for missing keys, so this is idempotent and preserves
-- any unknown future keys.
UPDATE source_configurations
SET connection_config = connection_config
    - 'address'
    - 'valid_tokens'
    - 'permit_origin'
    - 'tls'
WHERE config_type = 'splunk_hec';

-- Step 2: partial unique index. Only enforces uniqueness for splunk_hec
-- rows — http/vector/kafka/aws_s3/gcp_pubsub still support multiple
-- configs. If a tenant somehow has multiple splunk_hec rows pre-migration
-- (created before the NAN-883 application-level check shipped), this
-- statement will fail loudly with a duplicate-key error so the operator
-- can deduplicate manually. We intentionally do NOT auto-delete rows.
CREATE UNIQUE INDEX IF NOT EXISTS source_configurations_single_splunk_hec
    ON source_configurations (config_type)
    WHERE config_type = 'splunk_hec';

COMMENT ON INDEX source_configurations_single_splunk_hec IS
    'NAN-883: enforces that only one splunk_hec source configuration may exist. The OOTB listener (:8088) is shared; a user config is a routing profile over it. See SourceConfigService::is_single_instance_driver.';
