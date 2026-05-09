// SPDX-License-Identifier: AGPL-3.0-or-later

//! Status operations for log sources (enable/disable/toggle)

use uuid::Uuid;

use super::LogSourceService;
use super::LogSourceServiceError;
use crate::log_sources::types::LogSource;

impl LogSourceService {
    /// Enable a log source (must be validated first)
    pub async fn enable(&self, id: Uuid) -> Result<LogSource, LogSourceServiceError> {
        let log_source = self.repository().find_by_id(id).await?;

        if !log_source.validated {
            return Err(LogSourceServiceError::NotValidated);
        }

        Ok(self.repository().enable(id).await?)
    }

    /// Disable a log source
    pub async fn disable(&self, id: Uuid) -> Result<LogSource, LogSourceServiceError> {
        Ok(self.repository().disable(id).await?)
    }

    /// Toggle a log source's enabled status
    pub async fn toggle(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<LogSource, LogSourceServiceError> {
        if enabled {
            self.enable(id).await
        } else {
            self.disable(id).await
        }
    }
}
