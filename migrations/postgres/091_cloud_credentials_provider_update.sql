-- Update cloud_credentials provider check constraint to include all supported providers
-- Original constraint only allowed: aws_s3, azure_blob
-- Adding: gcp_pubsub, kafka, splunk_hec

ALTER TABLE public.cloud_credentials
    DROP CONSTRAINT cloud_credentials_provider_check;

ALTER TABLE public.cloud_credentials
    ADD CONSTRAINT cloud_credentials_provider_check
    CHECK (provider IN ('aws_s3', 'azure_blob', 'gcp_pubsub', 'kafka', 'splunk_hec'));

COMMENT ON COLUMN public.cloud_credentials.provider IS 'Cloud provider type: aws_s3, azure_blob, gcp_pubsub, kafka, or splunk_hec';
