-- Fix log source source_types that were incorrectly set to log type labels
-- instead of valid Vector source types (routed, file, syslog, http, kafka, aws_s3, etc.)
--
-- This ensures parsers receive events from the HTTP source router rather than
-- trying to create their own stdin sources (which conflict with each other).

UPDATE log_sources
SET source_type = 'routed'
WHERE source_type NOT IN (
    'routed',
    'file',
    'syslog',
    'http',
    'kafka',
    'aws_s3',
    'aws_sqs',
    'gcp_pubsub',
    'azure_blob'
);
