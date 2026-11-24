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
        // NAN-5789: a fetch source goes live only with a deployed source
        // configuration of its own type; otherwise the render leaves it out
        // and it would read as enabled while ingesting nothing.
        crate::log_sources::source_binding::ensure_binding(
            &self.pool,
            &log_source.kind,
            &log_source.source_type,
            log_source.dispatch_source_config_id,
            true,
        )
        .await
        .map_err(crate::log_sources::LogSourceRepositoryError::from)?
        .map_err(|e| LogSourceServiceError::MissingSourceConfiguration { field: e.field, message: e.message })?;

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
