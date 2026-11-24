// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5789: `source_type` is stored canonical, so the renderer classifies a
//! source exactly as the write-time checks did.

use super::crud::canonical_source_type;

#[test]
fn case_and_aliases_are_stored_canonical() {
    for (input, want) in [
        ("KAFKA", "kafka"),
        ("Aws_S3", "aws_s3"),
        ("s3", "aws_s3"),
        ("aws_sqs", "aws_sqs"),
        ("crowdstrike_fdr", "crowdstrike_fdr"),
        ("PubSub", "gcp_pubsub"),
        ("azure_event_hubs", "azure_event_hubs"),
        ("http", "routed"),
        ("Routed", "routed"),
        ("HEC", "splunk_hec"),
        ("vector", "vector"),
    ] {
        assert_eq!(canonical_source_type(input), want, "{input}");
    }
}
