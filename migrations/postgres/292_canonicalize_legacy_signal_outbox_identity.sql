-- NAN-2361: migrate beta Signal rows written before the durable outbox key was
-- stamped into both OCSF identity fields.
--
-- The historical shape used metadata.uid = <alert UUID> while the immutable
-- PostgreSQL key was alert:<UUID>[:<entity digest>]. Only that mechanically
-- provable relationship is rewritten. Unknown conflicts remain untouched and
-- therefore continue to fail closed at the Iceberg publisher.

UPDATE detection_finding_lake_outbox
SET ocsf_event = jsonb_set(
        jsonb_set(
            ocsf_event,
            '{metadata,uid}',
            to_jsonb(finding_id),
            false
        ),
        '{finding_info,uid}',
        to_jsonb(finding_id),
        false
    ),
    last_error = NULL
WHERE ocsf_event #>> '{metadata,uid}' IS NOT NULL
  AND ocsf_event #>> '{metadata,uid}' <> finding_id
  AND (
      finding_id = 'alert:' || (ocsf_event #>> '{metadata,uid}')
      OR finding_id LIKE 'alert:' || (ocsf_event #>> '{metadata,uid}') || ':%'
  );

COMMENT ON COLUMN detection_finding_lake_outbox.finding_id IS
    'Immutable Signal identity; canonical OCSF metadata.uid and finding_info.uid must match it.';
