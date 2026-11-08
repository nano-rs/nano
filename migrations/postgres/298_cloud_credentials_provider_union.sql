-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-4914: the cloud_credentials provider constraint as the UNION of every
-- provider any migration has admitted:
--   aws_s3, azure_blob, gcp_pubsub, kafka, splunk_hec  (007 / 091)
--   smtp                                               (297, NAN-4911 SOAR P4)
--   azure_event_hubs                                   (Event Hubs source configs)
--   okta, google_workspace, slack, saas_api            (connector pull-feed vendor secrets)
--
-- Idempotent and order-independent: it only ever widens the set, so it is
-- correct whether 297 ran before it, after it (out-of-order apply), or the
-- database already holds SMTP or connector credentials. Any later migration
-- that redefines this constraint must keep the full list, and the Rust
-- allowlist (`parsers::SUPPORTED_CREDENTIAL_PROVIDERS` + the legacy pair)
-- must match it (`credential_provider_tests` checks both).
SET LOCAL lock_timeout = '5s';

ALTER TABLE public.cloud_credentials
    DROP CONSTRAINT IF EXISTS cloud_credentials_provider_check;
ALTER TABLE public.cloud_credentials
    ADD CONSTRAINT cloud_credentials_provider_check
    CHECK (provider IN (
        'aws_s3', 'azure_blob', 'gcp_pubsub', 'kafka', 'splunk_hec', 'smtp',
        'azure_event_hubs', 'okta', 'google_workspace', 'slack', 'saas_api'
    ));

COMMENT ON COLUMN public.cloud_credentials.provider IS
    'Credential provider: aws_s3, gcp_pubsub, kafka, azure_event_hubs (source configs); smtp (outbound mail relay); okta, google_workspace, slack, saas_api (connector pull feeds); azure_blob and splunk_hec are legacy';
