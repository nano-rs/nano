// SPDX-License-Identifier: AGPL-3.0-or-later

//! Backup and restore support for Vector configuration.
//!
//! Provides rollback capability by backing up the active configuration
//! before deployment and restoring it if deployment fails.

use std::path::Path;

use tokio::fs;

use super::VectorConfigError;
use super::VectorConfigManager;

impl VectorConfigManager {
    /// Backup current active configuration for rollback support
    pub async fn backup_current(&self) -> Result<(), VectorConfigError> {
        // Remove old backup if it exists
        if self.backup_dir.exists() {
            fs::remove_dir_all(&self.backup_dir).await?;
        }

        // Only backup if parsers directory exists and has content
        if !self.parsers_dir.exists() {
            tracing::info!("No existing parsers directory to backup");
            return Ok(());
        }

        // Copy active parsers to backup
        self.copy_dir_recursive(&self.parsers_dir, &self.backup_dir)
            .await?;

        tracing::info!(
            "Backed up current config from {} to {}",
            self.parsers_dir.display(),
            self.backup_dir.display()
        );
        Ok(())
    }

    /// Restore configuration from backup
    /// Used for rollback when deployment fails
    pub async fn restore_backup(&self) -> Result<(), VectorConfigError> {
        if !self.backup_dir.exists() {
            return Err(VectorConfigError::NoBackupAvailable);
        }

        // Clear current parsers directory
        if self.parsers_dir.exists() {
            fs::remove_dir_all(&self.parsers_dir).await?;
        }

        // Restore from backup
        self.copy_dir_recursive(&self.backup_dir, &self.parsers_dir)
            .await?;

        tracing::info!(
            "Restored config from backup {} to {}",
            self.backup_dir.display(),
            self.parsers_dir.display()
        );
        Ok(())
    }

    /// Recursively copy a directory and its contents
    async fn copy_dir_recursive(&self, src: &Path, dst: &Path) -> Result<(), VectorConfigError> {
        // Create destination directory
        fs::create_dir_all(dst).await?;

        let mut entries = fs::read_dir(src).await?;
        while let Some(entry) = entries.next_entry().await? {
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            let file_type = entry.file_type().await?;

            if file_type.is_dir() {
                // Recursively copy subdirectory
                Box::pin(self.copy_dir_recursive(&src_path, &dst_path)).await?;
            } else if file_type.is_file() {
                // Copy file
                fs::copy(&src_path, &dst_path).await?;
            }
            // Skip symlinks and other file types for security
        }

        Ok(())
    }

    /// Check if a backup exists
    pub fn has_backup(&self) -> bool {
        self.backup_dir.exists()
    }

    /// Get the backup directory path
    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }

    /// Clean up backup directory
    pub async fn cleanup_backup(&self) -> Result<(), VectorConfigError> {
        if self.backup_dir.exists() {
            fs::remove_dir_all(&self.backup_dir).await?;
            tracing::info!("Cleaned up backup directory: {}", self.backup_dir.display());
        }
        Ok(())
    }
}
