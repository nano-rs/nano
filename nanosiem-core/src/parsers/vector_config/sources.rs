// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source-specific Vector configuration generators.
//!
//! Generates TOML configuration blocks for different Vector source types:
//! Kafka, AWS S3/SQS, GCP Pub/Sub, and Splunk HEC.

use super::VectorConfigManager;
use crate::parsers::types::Parser;
use crate::source_configs::service::normalize_pubsub_subscription;

impl VectorConfigManager {
    /// Generate source configuration for a parser
    ///
    /// For "routed" source type, no source is created - the parser takes input
    /// from the HTTP router (source_router.{parser_name}) instead.
    pub(super) fn generate_source_config(&self, parser: &Parser) -> (String, String) {
        let safe_name = Self::safe_name(&parser.name);

        match parser.source_type.as_str() {
            "routed" => {
                // Routed parsers take input from the HTTP source router
                // No source config needed - the transform will use source_router.{name}
                let router_input = format!("source_router.{}", safe_name);
                (String::new(), router_input)
            }
            "kafka" => {
                let source_name = format!("{}_source", safe_name);
                let config = self.generate_kafka_source(parser, &source_name);
                (config, source_name)
            }
            "aws_s3" | "aws_sqs" => {
                let source_name = format!("{}_source", safe_name);
                let config = self.generate_s3_source(parser, &source_name);
                (config, source_name)
            }
            "gcp_pubsub" => {
                let source_name = format!("{}_source", safe_name);
                let config = self.generate_gcp_pubsub_source(parser, &source_name);
                (config, source_name)
            }
            "splunk_hec" | "splunk" | "hec" => {
                let source_name = format!("{}_source", safe_name);
                let config = self.generate_splunk_hec_source(parser, &source_name);
                (config, source_name)
            }
            "vector" => {
                // Vector-to-Vector source is handled at infrastructure level in 01-vector-source.toml
                // Events arrive with source_type already set by the upstream aggregator
                // Events flow through the router (which has vector_merge as input) for proper
                // source_type-based routing, just like HTTP ingestion events.
                let router_input = format!("source_router.{}", safe_name);
                (String::new(), router_input)
            }
            _ => {
                // Unknown source types default to routed (receive from HTTP source router)
                // This handles cases where source_type is a log type label (e.g., "apache_access")
                // rather than a Vector source type (e.g., "file", "syslog", "http")
                let router_input = format!("source_router.{}", safe_name);
                tracing::debug!(
                    "Parser '{}' has unrecognized source_type '{}', defaulting to routed",
                    parser.name,
                    parser.source_type
                );
                (String::new(), router_input)
            }
        }
    }

    /// Generate Kafka source configuration with optional SASL/TLS authentication
    ///
    /// SASL mechanisms supported: PLAIN, SCRAM-SHA-256, SCRAM-SHA-512
    /// TLS: optional CA certificate for server verification
    fn generate_kafka_source(&self, parser: &Parser, source_name: &str) -> String {
        let config = &parser.source_config;
        let bootstrap_servers = config["bootstrap_servers"]
            .as_str()
            .unwrap_or("localhost:9092");
        let topics = config["topics"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "\"logs\"".to_string());
        let group_id = config["group_id"].as_str().unwrap_or("nanosiem");
        let auto_offset_reset = config["auto_offset_reset"].as_str().unwrap_or("largest");

        let mut source_config = format!(
            "[sources.{}]\n\
             type = \"kafka\"\n\
             bootstrap_servers = \"{}\"\n\
             topics = [{}]\n\
             group_id = \"{}\"\n\
             auto_offset_reset = \"{}\"\n",
            source_name, bootstrap_servers, topics, group_id, auto_offset_reset
        );

        // Check for embedded credentials (decrypted and passed via source_config)
        if let Some(creds) = config.get("_credentials") {
            // SASL authentication
            if let Some(mechanism) = creds["sasl_mechanism"].as_str() {
                if !mechanism.is_empty() {
                    let username = creds["sasl_username"].as_str().unwrap_or("");
                    let password = creds["sasl_password"].as_str().unwrap_or("");

                    source_config.push_str(&format!(
                        "\n[sources.{}.sasl]\n\
                         enabled = true\n\
                         mechanism = \"{}\"\n\
                         username = \"{}\"\n\
                         password = \"{}\"\n",
                        source_name, mechanism, username, password
                    ));
                }
            }

            // TLS configuration
            let tls_enabled = creds["tls_enabled"].as_bool().unwrap_or(false);
            if tls_enabled {
                source_config.push_str(&format!(
                    "\n[sources.{}.tls]\n\
                     enabled = true\n",
                    source_name
                ));

                // Optional CA certificate - written to parsers_dir for S3/GCS sync
                if let Some(ca_cert) = creds["tls_ca_cert"].as_str() {
                    if !ca_cert.is_empty() {
                        let safe = Self::safe_name(&parser.name);
                        let ca_path = self.parser_creds_runtime(&format!("kafka_{}_ca.pem", safe));
                        source_config.push_str(&format!("ca_file = \"{}\"\n", ca_path));
                    }
                }
            }
        }

        source_config
    }

    /// Generate AWS S3 source configuration
    ///
    /// IMPORTANT: Vector's aws_s3 source requires an SQS queue configured to receive
    /// S3 bucket notifications. It does NOT poll S3 directly.
    ///
    /// Required config:
    /// - sqs_queue_url: The SQS queue URL that receives S3 notifications
    /// - region: AWS region
    ///
    /// Optional config:
    /// - compression: auto, gzip, zstd, none
    /// - endpoint: S3-compatible endpoint (MinIO, etc.)
    /// - _credentials: AWS credentials (access_key_id, secret_access_key, etc.)
    fn generate_s3_source(&self, parser: &Parser, source_name: &str) -> String {
        let config = &parser.source_config;
        let sqs_queue_url = config["sqs_queue_url"].as_str().unwrap_or("");
        let region = config["region"].as_str().unwrap_or("us-east-1");

        // Check for S3-compatible endpoint (MinIO, etc.)
        let endpoint_config = if let Some(endpoint) = config["endpoint"].as_str() {
            format!("endpoint = \"{}\"\n", endpoint)
        } else {
            String::new()
        };

        // Compression handling
        let compression_config = match config["compression"].as_str() {
            Some("gzip") => "compression = \"gzip\"\n",
            Some("zstd") => "compression = \"zstd\"\n",
            Some("none") => "compression = \"none\"\n",
            _ => "", // Auto-detect
        };

        // Check for embedded credentials (decrypted and passed via source_config)
        let auth_config = if let Some(creds) = config.get("_credentials") {
            let access_key = creds["access_key_id"].as_str().unwrap_or("");
            let secret_key = creds["secret_access_key"].as_str().unwrap_or("");

            if !access_key.is_empty() && !secret_key.is_empty() {
                let mut auth = format!(
                    "\n[sources.{}.auth]\n\
                     access_key_id = \"{}\"\n\
                     secret_access_key = \"{}\"\n\
                     region = \"{}\"\n",
                    source_name, access_key, secret_key, region
                );

                // Add session token if present
                if let Some(token) = creds["session_token"].as_str() {
                    if !token.is_empty() {
                        auth.push_str(&format!("session_token = \"{}\"\n", token));
                    }
                }

                // Add assume role if present
                if let Some(role) = creds["assume_role_arn"].as_str() {
                    if !role.is_empty() {
                        auth.push_str(&format!("assume_role = \"{}\"\n", role));
                    }
                }

                auth
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        // SQS configuration section
        let sqs_config = format!(
            "\n[sources.{}.sqs]\n\
             queue_url = \"{}\"\n\
             poll_secs = 15\n\
             delete_message = true\n",
            source_name, sqs_queue_url
        );

        format!(
            "[sources.{}]\n\
             type = \"aws_s3\"\n\
             region = \"{}\"\n\
             {}\
             {}\
             {}\
             {}\n",
            source_name,
            region,
            endpoint_config,
            compression_config,
            sqs_config.trim_end(),
            auth_config.trim_end()
        )
    }

    /// Generate GCP Pub/Sub source configuration
    ///
    /// Vector's gcp_pubsub source pulls messages from a subscription.
    ///
    /// Required config:
    /// - project: GCP project ID
    /// - subscription: Pub/Sub subscription name
    ///
    /// Optional config:
    /// - ack_deadline_secs: Acknowledgement deadline (default: 600)
    /// - endpoint: Custom Pub/Sub endpoint (for emulators)
    /// - _credentials: Service account JSON key (written to file, referenced via credentials_path)
    ///
    /// Authentication (in order of precedence):
    /// 1. credentials_path - Path to service account JSON file
    /// 2. api_key - GCP API key
    /// 3. GOOGLE_APPLICATION_CREDENTIALS env var
    /// 4. Instance metadata (GCE/GKE)
    fn generate_gcp_pubsub_source(&self, parser: &Parser, source_name: &str) -> String {
        let config = &parser.source_config;
        let project = config["project"].as_str().unwrap_or("");
        let subscription_raw = config["subscription"].as_str().unwrap_or("");
        let subscription = normalize_pubsub_subscription(subscription_raw);
        let ack_deadline = config["ack_deadline_secs"].as_u64().unwrap_or(600);

        if project.is_empty() || subscription.is_empty() {
            tracing::warn!(
                "GCP Pub/Sub source '{}' missing project or subscription",
                parser.name
            );
            return format!(
                "# WARNING: GCP Pub/Sub source requires project and subscription\n\
                 # Please configure source_config for this parser\n\
                 [sources.{}]\n\
                 type = \"gcp_pubsub\"\n\
                 project = \"<MISSING>\"\n\
                 subscription = \"<MISSING>\"\n",
                source_name
            );
        }

        let mut source_config = format!(
            "[sources.{}]\n\
             type = \"gcp_pubsub\"\n\
             project = \"{}\"\n\
             subscription = \"{}\"\n\
             ack_deadline_secs = {}\n",
            source_name, project, subscription, ack_deadline
        );

        // Optional custom endpoint (for emulators or private endpoints)
        if let Some(endpoint) = config["endpoint"].as_str() {
            if !endpoint.is_empty() {
                source_config.push_str(&format!("endpoint = \"{}\"\n", endpoint));
            }
        }

        // Check for embedded credentials (decrypted and passed via source_config)
        // Vector uses credentials_path to point to a service account JSON file
        if let Some(creds) = config.get("_credentials") {
            if let Some(credentials_json) = creds["credentials_json"].as_str() {
                if !credentials_json.is_empty() {
                    // Credentials are written to parsers_dir for S3/GCS sync.
                    // Runtime path resolves to where Vector reads parser configs.
                    let safe = Self::safe_name(&parser.name);
                    let creds_path = self.parser_creds_runtime(&format!("gcp_{}.creds", safe));
                    source_config.push_str(&format!("credentials_path = \"{}\"\n", creds_path));
                }
            }
        } else {
            source_config
                .push_str("# Using default GCP credentials (ADC, env var, or instance metadata)\n");
        }

        source_config
    }

    /// Generate Splunk HEC source configuration
    ///
    /// Splunk's HTTP Event Collector (HEC) is a common log shipping protocol.
    /// Vector can act as a HEC endpoint to receive logs from any HEC-speaking forwarder.
    ///
    /// Required config:
    /// - address: Listen address (e.g., "0.0.0.0:8088")
    /// - valid_tokens: Array of valid HEC tokens for authentication
    ///
    /// Optional config:
    /// - permit_origin: IP allowlist in CIDR notation
    /// - tls: TLS configuration for HTTPS
    fn generate_splunk_hec_source(&self, parser: &Parser, source_name: &str) -> String {
        let config = &parser.source_config;
        let address = config["address"].as_str().unwrap_or("0.0.0.0:8088");

        let mut source_config = format!(
            "[sources.{}]\n\
             type = \"splunk_hec\"\n\
             address = \"{}\"\n",
            source_name, address
        );

        // Add valid tokens (required for authentication)
        if let Some(tokens) = config["valid_tokens"].as_array() {
            if !tokens.is_empty() {
                let token_list: Vec<String> = tokens
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| format!("\"{}\"", s))
                    .collect();
                if !token_list.is_empty() {
                    source_config
                        .push_str(&format!("valid_tokens = [{}]\n", token_list.join(", ")));
                }
            }
        }

        // Add IP allowlist if configured
        if let Some(permit_origin) = config["permit_origin"].as_array() {
            if !permit_origin.is_empty() {
                let origins: Vec<String> = permit_origin
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| format!("\"{}\"", s))
                    .collect();
                if !origins.is_empty() {
                    source_config.push_str(&format!("permit_origin = [{}]\n", origins.join(", ")));
                }
            }
        }

        // Add TLS configuration if enabled
        // Cert files are written by write_credential_files() and referenced by managed path
        if let Some(tls) = config.get("tls") {
            let tls_enabled = tls["enabled"].as_bool().unwrap_or(false);
            if tls_enabled {
                source_config.push_str(&format!("\n[sources.{}.tls]\n", source_name));
                source_config.push_str("enabled = true\n");

                // Credential files written to parsers_dir for S3/GCS sync
                let safe = Self::safe_name(&parser.name);
                // Server certificate (required for TLS)
                if let Some(crt_content) = tls["crt_content"].as_str() {
                    if !crt_content.is_empty() {
                        let crt_path =
                            self.parser_creds_runtime(&format!("splunk_hec_{}_crt.pem", safe));
                        source_config.push_str(&format!("crt_file = \"{}\"\n", crt_path));
                    }
                }
                // Private key (required for TLS)
                if let Some(key_content) = tls["key_content"].as_str() {
                    if !key_content.is_empty() {
                        let key_path =
                            self.parser_creds_runtime(&format!("splunk_hec_{}_key.pem", safe));
                        source_config.push_str(&format!("key_file = \"{}\"\n", key_path));
                    }
                }
                // CA certificate (optional, for client verification)
                if let Some(ca_content) = tls["ca_content"].as_str() {
                    if !ca_content.is_empty() {
                        let ca_path =
                            self.parser_creds_runtime(&format!("splunk_hec_{}_ca.pem", safe));
                        source_config.push_str(&format!("ca_file = \"{}\"\n", ca_path));
                    }
                }
            }
        }

        source_config
    }
}
