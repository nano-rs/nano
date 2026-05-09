// SPDX-License-Identifier: AGPL-3.0-or-later

//! Credential file management for Vector parser sources.
//!
//! Handles writing and removing credential files (GCP service account JSON,
//! Kafka CA certificates, TLS certificates) for parser source configurations.

use tokio::fs;

use super::VectorConfigError;
use super::VectorConfigManager;
use crate::parsers::types::Parser;

impl VectorConfigManager {
    /// Write credential files for a parser (e.g., GCP service account JSON, TLS certs)
    ///
    /// Credentials are written via `parser_creds_path`, which places them directly
    /// under `sources_dir` with a `parsers__` prefix. This survives K8s ConfigMap
    /// key flattening (keys can't contain `/`) so the same `credentials_path`
    /// resolves in Docker, S3-synced K8s, and ConfigMap-synced K8s.
    pub(super) async fn write_credential_files(
        &self,
        parser: &Parser,
    ) -> Result<(), VectorConfigError> {
        let safe_name = Self::safe_name(&parser.name);

        // Handle GCP Pub/Sub credentials
        if parser.source_type == "gcp_pubsub" {
            if let Some(creds) = parser.source_config.get("_credentials") {
                if let Some(credentials_json) = creds["credentials_json"].as_str() {
                    if !credentials_json.is_empty() {
                        let creds_path =
                            self.parser_creds_path(&format!("gcp_{}.creds", safe_name));
                        fs::write(&creds_path, credentials_json).await?;
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let perms = std::fs::Permissions::from_mode(0o644);
                            std::fs::set_permissions(&creds_path, perms).ok();
                        }
                        tracing::info!(
                            "Wrote GCP credentials for parser '{}' to {}",
                            parser.name,
                            creds_path.display()
                        );
                    }
                }
            }
        }

        // Handle Kafka TLS CA certificate (from credentials system)
        if parser.source_type == "kafka" {
            if let Some(creds) = parser.source_config.get("_credentials") {
                let tls_enabled = creds["tls_enabled"].as_bool().unwrap_or(false);
                if tls_enabled {
                    if let Some(ca_cert) = creds["tls_ca_cert"].as_str() {
                        if !ca_cert.is_empty() {
                            let ca_path =
                                self.parser_creds_path(&format!("kafka_{}_ca.pem", safe_name));
                            fs::write(&ca_path, ca_cert).await?;
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let perms = std::fs::Permissions::from_mode(0o644);
                                std::fs::set_permissions(&ca_path, perms).ok();
                            }
                            tracing::info!(
                                "Wrote Kafka CA certificate for parser '{}' to {}",
                                parser.name,
                                ca_path.display()
                            );
                        }
                    }
                }
            }
        }

        // Handle TLS certificates for source types that store them in source_config.tls
        // This includes: syslog, splunk_hec, opentelemetry, fluent
        let tls_source_types = ["syslog", "splunk_hec", "opentelemetry", "fluent"];
        if tls_source_types.contains(&parser.source_type.as_str()) {
            if let Some(tls) = parser.source_config.get("tls") {
                let tls_enabled = tls["enabled"].as_bool().unwrap_or(false);
                if tls_enabled {
                    // Write CA certificate if provided
                    if let Some(ca_content) = tls["ca_content"].as_str() {
                        if !ca_content.is_empty() {
                            let ca_path = self.parser_creds_path(&format!(
                                "{}_{}_ca.pem",
                                parser.source_type, safe_name
                            ));
                            fs::write(&ca_path, ca_content).await?;
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let perms = std::fs::Permissions::from_mode(0o644);
                                std::fs::set_permissions(&ca_path, perms).ok();
                            }
                            tracing::info!(
                                "Wrote {} CA certificate for parser '{}' to {}",
                                parser.source_type,
                                parser.name,
                                ca_path.display()
                            );
                        }
                    }

                    // Write server certificate if provided
                    if let Some(crt_content) = tls["crt_content"].as_str() {
                        if !crt_content.is_empty() {
                            let crt_path = self.parser_creds_path(&format!(
                                "{}_{}_crt.pem",
                                parser.source_type, safe_name
                            ));
                            fs::write(&crt_path, crt_content).await?;
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let perms = std::fs::Permissions::from_mode(0o644);
                                std::fs::set_permissions(&crt_path, perms).ok();
                            }
                            tracing::info!(
                                "Wrote {} server certificate for parser '{}' to {}",
                                parser.source_type,
                                parser.name,
                                crt_path.display()
                            );
                        }
                    }

                    // Write private key if provided (more restrictive permissions)
                    if let Some(key_content) = tls["key_content"].as_str() {
                        if !key_content.is_empty() {
                            let key_path = self.parser_creds_path(&format!(
                                "{}_{}_key.pem",
                                parser.source_type, safe_name
                            ));
                            fs::write(&key_path, key_content).await?;
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                // Private key gets more restrictive permissions
                                let perms = std::fs::Permissions::from_mode(0o600);
                                std::fs::set_permissions(&key_path, perms).ok();
                            }
                            tracing::info!(
                                "Wrote {} private key for parser '{}' to {}",
                                parser.source_type,
                                parser.name,
                                key_path.display()
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Remove credential files for a parser. Cleans up the current flat layout,
    /// the previous parsers/-subdir layout, and the original credentials_dir
    /// layout so an upgrade across any of those leaves no orphaned secrets.
    pub(super) async fn remove_credential_files(
        &self,
        parser: &Parser,
    ) -> Result<(), VectorConfigError> {
        let safe_name = Self::safe_name(&parser.name);
        let source_name = format!("{}_source", safe_name);

        // Remove GCP credentials file
        for path in [
            self.parser_creds_path(&format!("gcp_{}.creds", safe_name)),
            self.parsers_dir.join(format!("gcp_{}.creds", safe_name)),
            self.credentials_dir
                .join(format!("gcp_{}.json", source_name)),
        ] {
            if path.exists() {
                fs::remove_file(&path).await?;
                tracing::info!("Removed GCP credentials file: {}", path.display());
            }
        }

        // Remove Kafka CA certificate
        for path in [
            self.parser_creds_path(&format!("kafka_{}_ca.pem", safe_name)),
            self.parsers_dir
                .join(format!(".kafka_{}_ca.pem", safe_name)),
            self.credentials_dir
                .join(format!("kafka_{}_ca.pem", source_name)),
        ] {
            if path.exists() {
                fs::remove_file(&path).await?;
                tracing::info!("Removed Kafka CA certificate: {}", path.display());
            }
        }

        // Remove TLS certificates for source types that store them in source_config.tls
        let tls_source_types = ["syslog", "splunk_hec", "opentelemetry", "fluent"];
        for source_type in tls_source_types {
            for (suffix, label) in [
                ("ca", "CA certificate"),
                ("crt", "server certificate"),
                ("key", "private key"),
            ] {
                for path in [
                    self.parser_creds_path(&format!(
                        "{}_{}_{}.pem",
                        source_type, safe_name, suffix
                    )),
                    self.parsers_dir
                        .join(format!(".{}_{}_{}.pem", source_type, safe_name, suffix)),
                    self.credentials_dir
                        .join(format!("{}_{}_{}.pem", source_type, source_name, suffix)),
                ] {
                    if path.exists() {
                        fs::remove_file(&path).await?;
                        tracing::info!("Removed {} {}: {}", source_type, label, path.display());
                    }
                }
            }
        }

        Ok(())
    }
}
