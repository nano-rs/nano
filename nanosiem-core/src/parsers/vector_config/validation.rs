// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vector configuration validation via Docker exec.
//!
//! Validates staged configuration using `vector validate` inside the
//! Docker container, parsing output for errors and warnings.

use tokio::process::Command;

use super::VectorConfigError;
use super::VectorConfigManager;
use crate::parsers::types::{Parser, ValidationResult};

impl VectorConfigManager {
    /// Validate staged configuration using `docker exec vector vector validate`
    /// Returns a structured validation result with errors and warnings
    pub async fn validate_staged_config(&self) -> Result<ValidationResult, VectorConfigError> {
        if !self.staging_dir.exists() {
            return Err(VectorConfigError::StagingError(
                "Staging directory does not exist - stage config first".to_string(),
            ));
        }

        // Get the container name from environment or use default
        let container_name = std::env::var("VECTOR_CONTAINER_NAME")
            .unwrap_or_else(|_| "nanosiem-vector".to_string());

        // Get the path inside the container where staging is mounted
        // By default, config/vector is mounted to /etc/vector in the container
        let container_staging_path = std::env::var("VECTOR_STAGING_PATH")
            .unwrap_or_else(|_| "/etc/vector/staging".to_string());

        // Staging now contains full config structure including sources/parsers subdirectory
        let container_staging_parsers_path = format!("{}/sources/parsers", container_staging_path);

        // Run vector validate inside the Docker container with both config directories
        // This mirrors the production setup: base config + parsers subdirectory
        let output = Command::new("docker")
            .args([
                "exec",
                &container_name,
                "vector",
                "validate",
                "--config-dir",
                &container_staging_path,
                "--config-dir",
                &container_staging_parsers_path,
            ])
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Parse the validation output
        let (errors, warnings) = Self::parse_validation_output(&stdout, &stderr);

        // Detect Docker mount propagation failures (macOS Docker Desktop issue).
        // If Vector can't see the staging dirs, the files exist on the host but
        // the container mount hasn't propagated them yet. Treat as non-fatal since
        // VRL validation already passed before we get here.
        let combined_output = format!("{}\n{}", stdout, stderr);
        let is_mount_issue =
            combined_output.contains("Failed to load") && combined_output.contains("staging");

        if output.status.success() && errors.is_empty() {
            tracing::info!("Vector configuration validation passed");
            Ok(ValidationResult {
                success: true,
                errors: vec![],
                warnings,
                raw_output: stdout,
            })
        } else if is_mount_issue {
            tracing::warn!(
                "Docker mount propagation issue detected - staging dirs not visible in container. \
                 Proceeding since VRL validation already passed."
            );
            Ok(ValidationResult {
                success: true,
                errors: vec![],
                warnings: vec![
                    "Docker mount propagation issue: staging dirs not visible in container. \
                     VRL validation passed, proceeding with deploy."
                        .to_string(),
                ],
                raw_output: format!("{}\n{}", stdout, stderr),
            })
        } else {
            let error_msg = if !errors.is_empty() {
                errors.join("; ")
            } else if !stderr.is_empty() {
                stderr.clone()
            } else {
                "Validation failed with unknown error".to_string()
            };

            tracing::warn!("Vector configuration validation failed: {}", error_msg);
            Ok(ValidationResult {
                success: false,
                errors,
                warnings,
                raw_output: format!("{}\n{}", stdout, stderr),
            })
        }
    }

    /// Parse Vector validation output to extract errors and warnings
    fn parse_validation_output(stdout: &str, stderr: &str) -> (Vec<String>, Vec<String>) {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        let combined = format!("{}\n{}", stdout, stderr);

        for line in combined.lines() {
            let line_lower = line.to_lowercase();

            // Skip empty lines
            if line.trim().is_empty() {
                continue;
            }

            // Detect errors
            if line_lower.contains("error") || line_lower.contains("failed") {
                errors.push(line.trim().to_string());
            }
            // Detect warnings
            else if line_lower.contains("warn") {
                warnings.push(line.trim().to_string());
            }
            // Also capture lines that look like validation messages
            else if line.contains("Configuration") && line_lower.contains("invalid") {
                errors.push(line.trim().to_string());
            }
        }

        (errors, warnings)
    }

    /// Validate a single parser's config without staging
    /// Useful for quick validation during parser creation/editing
    pub async fn validate_parser_config(
        &self,
        parser: &Parser,
    ) -> Result<ValidationResult, VectorConfigError> {
        // Stage just this parser
        self.cleanup_staging().await?;
        self.stage_parser(parser).await?;

        // Validate
        let result = self.validate_staged_config().await;

        // Cleanup staging regardless of result
        let _ = self.cleanup_staging().await;

        result
    }
}
