-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-4911 P4: an `smtp` credential provider, so an outbound mail relay's
-- password is sealed in the credentials store (versioned, `credentials:use`
-- gated) like every other stored secret instead of a feature-private column.
--
-- Future migrations that redefine cloud_credentials_provider_check must keep
-- 'smtp' in the list, or the ADD CONSTRAINT fails on a database holding one.
SET LOCAL lock_timeout = '5s';

ALTER TABLE public.cloud_credentials
    DROP CONSTRAINT IF EXISTS cloud_credentials_provider_check;
ALTER TABLE public.cloud_credentials
    ADD CONSTRAINT cloud_credentials_provider_check
    CHECK (provider IN ('aws_s3', 'azure_blob', 'gcp_pubsub', 'kafka', 'splunk_hec', 'smtp'));

COMMENT ON COLUMN public.cloud_credentials.provider IS
    'Credential provider type: aws_s3, azure_blob, gcp_pubsub, kafka, splunk_hec, or smtp';
