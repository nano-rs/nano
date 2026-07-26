// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cleanup for files created by the removed parser-owned credential path.

use tokio::fs;

use super::VectorConfigError;
use super::VectorConfigManager;
use crate::parsers::types::Parser;

impl VectorConfigManager {
    /// Remove credential files written by legacy parser-owned transports.
    ///
    /// Modern transport credentials are owned by source_configurations and use
    /// that subsystem's credential backend. This cleanup intentionally writes
    /// nothing; it only prevents secrets from the retired path lingering after
    /// an upgrade.
    pub(super) async fn remove_legacy_parser_credential_files(
        &self,
        parser: &Parser,
    ) -> Result<(), VectorConfigError> {
        let safe_name = Self::safe_name(&parser.name);
        let source_name = format!("{}_source", safe_name);

        for path in [
            self.parser_creds_path(&format!("gcp_{}.creds", safe_name)),
            self.parsers_dir.join(format!("gcp_{}.creds", safe_name)),
            self.credentials_dir
                .join(format!("gcp_{}.json", source_name)),
            self.parser_creds_path(&format!("kafka_{}_ca.pem", safe_name)),
            self.parsers_dir
                .join(format!(".kafka_{}_ca.pem", safe_name)),
            self.credentials_dir
                .join(format!("kafka_{}_ca.pem", source_name)),
        ] {
            if path.exists() {
                fs::remove_file(&path).await?;
                tracing::info!("Removed legacy parser credential file: {}", path.display());
            }
        }

        for source_type in ["syslog", "splunk_hec", "opentelemetry", "fluent"] {
            for suffix in ["ca", "crt", "key"] {
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
                        tracing::info!("Removed legacy parser credential file: {}", path.display());
                    }
                }
            }
        }

        Ok(())
    }
}
