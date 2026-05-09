// SPDX-License-Identifier: AGPL-3.0-or-later

//! Health monitoring scheduler
//!
//! Background task that periodically checks AI provider and feed health,
//! creates notifications for issues, and tracks issue resolution.

use clickhouse::Client as ClickHouseClient;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use crate::audit::{AuditEmitter, AuditEvent, AuditSource};
use crate::db::repository::NotificationRepository;
use crate::db::DualPool;
use crate::models::notification::{NewNotification, NotificationType};

use super::ai_monitor::AiMonitor;
use super::feed_monitor::FeedMonitor;
use super::repository::HealthRepository;
use super::types::{HealthIssueType, HealthSchedulerConfig};

/// Health monitoring scheduler
pub struct HealthScheduler {
    config: HealthSchedulerConfig,
    health_repo: HealthRepository,
    notification_repo: NotificationRepository,
    ai_monitor: AiMonitor,
    feed_monitor: FeedMonitor,
    audit_emitter: AuditEmitter,
}

impl HealthScheduler {
    /// Create a new scheduler with PostgreSQL only
    pub fn new(pool: PgPool, config: HealthSchedulerConfig) -> Self {
        Self {
            config,
            health_repo: HealthRepository::new(pool.clone()),
            notification_repo: NotificationRepository::new(pool.clone()),
            ai_monitor: AiMonitor::new(pool.clone()),
            feed_monitor: FeedMonitor::new(pool),
            audit_emitter: AuditEmitter::noop(),
        }
    }

    /// Create a new scheduler with ClickHouse support (legacy - prefer with_dual_pool)
    pub fn with_clickhouse(
        pool: PgPool,
        ch_client: ClickHouseClient,
        config: HealthSchedulerConfig,
    ) -> Self {
        Self {
            config,
            health_repo: HealthRepository::new(pool.clone()),
            notification_repo: NotificationRepository::new(pool.clone()),
            ai_monitor: AiMonitor::new(pool.clone()),
            feed_monitor: FeedMonitor::with_clickhouse(pool, ch_client),
            audit_emitter: AuditEmitter::noop(),
        }
    }

    /// Create a new scheduler with DualPool support (recommended)
    pub fn with_dual_pool(
        pool: PgPool,
        dual_pool: DualPool,
        config: HealthSchedulerConfig,
    ) -> Self {
        Self {
            config,
            health_repo: HealthRepository::new(pool.clone()),
            notification_repo: NotificationRepository::new(pool.clone()),
            ai_monitor: AiMonitor::new(pool.clone()),
            feed_monitor: FeedMonitor::with_clickhouse(pool, dual_pool.clickhouse().clone()),
            audit_emitter: AuditEmitter::new(dual_pool),
        }
    }

    /// Start the scheduler as a background task
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!(
                interval_secs = self.config.check_interval_secs,
                "Starting health monitoring scheduler"
            );

            let mut check_interval = interval(Duration::from_secs(self.config.check_interval_secs));
            // Skip initial tick
            check_interval.tick().await;

            loop {
                check_interval.tick().await;
                self.run_health_checks().await;
            }
        })
    }

    /// Run all health checks
    async fn run_health_checks(&self) {
        debug!("Running health checks");

        // Check AI providers (if enabled - costs API credits)
        if self.is_ai_monitoring_enabled().await {
            if let Err(e) = self.check_ai_providers().await {
                error!(error = %e, "Failed to check AI providers");
            }
        } else {
            debug!("AI monitoring disabled, skipping provider checks");
        }

        // Check feed staleness (if enabled - free, just DB queries)
        if self.is_feed_monitoring_enabled().await {
            if let Err(e) = self.check_feed_staleness().await {
                error!(error = %e, "Failed to check feed staleness");
            }
        } else {
            debug!("Feed monitoring disabled, skipping staleness checks");
        }
    }

    /// Check if AI provider monitoring is enabled
    async fn is_ai_monitoring_enabled(&self) -> bool {
        self.health_repo
            .is_ai_monitoring_enabled()
            .await
            .unwrap_or(false)
    }

    /// Check if feed staleness monitoring is enabled
    async fn is_feed_monitoring_enabled(&self) -> bool {
        self.health_repo
            .is_feed_monitoring_enabled()
            .await
            .unwrap_or(true)
    }

    /// Check all AI providers
    async fn check_ai_providers(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let statuses = self.ai_monitor.check_all_providers().await;

        for status in statuses {
            let issue_key = status.provider_type.clone();

            if !status.is_healthy {
                // Provider is down - create or update issue
                let existing = self
                    .health_repo
                    .find_active_issue(&HealthIssueType::AiProvider.to_string(), &issue_key)
                    .await?;

                if let Some(issue) = existing {
                    if !issue.notification_sent {
                        // Send notification
                        self.send_ai_provider_notification(&status).await?;
                        self.health_repo.mark_notification_sent(issue.id).await?;
                    }
                } else {
                    // Create new issue
                    let issue = self
                        .health_repo
                        .create_issue(&HealthIssueType::AiProvider.to_string(), &issue_key)
                        .await?;

                    // Send notification
                    self.send_ai_provider_notification(&status).await?;
                    self.health_repo.mark_notification_sent(issue.id).await?;
                }
            } else {
                // Provider is healthy - resolve any existing issue
                self.health_repo
                    .resolve_issue(&HealthIssueType::AiProvider.to_string(), &issue_key)
                    .await?;
            }
        }

        Ok(())
    }

    /// Check all feeds for staleness
    async fn check_feed_staleness(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let statuses = self.feed_monitor.check_all_feeds().await;

        for status in statuses {
            let issue_key = status.feed_id.to_string();

            if status.is_stale {
                // Feed is stale - create or update issue
                let existing = self
                    .health_repo
                    .find_active_issue(&HealthIssueType::DataFeed.to_string(), &issue_key)
                    .await?;

                if let Some(issue) = existing {
                    if !issue.notification_sent {
                        // Send notification
                        self.send_feed_stale_notification(&status).await?;
                        self.health_repo.mark_notification_sent(issue.id).await?;
                    }
                } else {
                    // Create new issue
                    let issue = self
                        .health_repo
                        .create_issue(&HealthIssueType::DataFeed.to_string(), &issue_key)
                        .await?;

                    // Send notification
                    self.send_feed_stale_notification(&status).await?;
                    self.health_repo.mark_notification_sent(issue.id).await?;

                    // Emit audit event for feed staleness
                    self.emit_feed_stale_audit(&status).await;
                }
            } else {
                // Feed is healthy - resolve any existing issue
                self.health_repo
                    .resolve_issue(&HealthIssueType::DataFeed.to_string(), &issue_key)
                    .await?;
            }
        }

        Ok(())
    }

    /// Send notification for AI provider being down
    async fn send_ai_provider_notification(
        &self,
        status: &super::types::AiProviderStatus,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let admin_user_ids = self.health_repo.get_admin_user_ids().await?;

        if admin_user_ids.is_empty() {
            warn!("No admin users found to notify about AI provider issue");
            return Ok(());
        }

        let error_detail = status
            .error_message
            .as_ref()
            .map(|e| format!(": {}", e))
            .unwrap_or_default();

        for user_id in admin_user_ids {
            let notification = NewNotification {
                user_id,
                notification_type: NotificationType::AiProviderDown,
                title: format!("AI Provider Down: {}", status.provider_name),
                message: Some(format!(
                    "The {} AI provider is not responding{}",
                    status.provider_name, error_detail
                )),
                link: Some("/melod".to_string()),
                metadata: serde_json::json!({
                    "provider_type": status.provider_type,
                    "provider_name": status.provider_name,
                    "error_message": status.error_message,
                }),
            };

            if let Err(e) = self.notification_repo.create(&notification).await {
                warn!(
                    user_id = %user_id,
                    provider = %status.provider_name,
                    error = %e,
                    "Failed to create AI provider down notification"
                );
            }
        }

        info!(
            provider = %status.provider_name,
            "Sent AI provider down notifications to admin users"
        );

        Ok(())
    }

    /// Send notification for stale feed
    async fn send_feed_stale_notification(
        &self,
        status: &super::types::FeedStalenessStatus,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let admin_user_ids = self.health_repo.get_admin_user_ids().await?;

        if admin_user_ids.is_empty() {
            warn!("No admin users found to notify about stale feed");
            return Ok(());
        }

        let staleness_detail = status
            .minutes_since_last_event
            .map(|m| {
                if m >= 60 {
                    format!("No data received in {} hours", m / 60)
                } else {
                    format!("No data received in {} minutes", m)
                }
            })
            .unwrap_or_else(|| "No data has ever been received".to_string());

        for user_id in admin_user_ids {
            let notification = NewNotification {
                user_id,
                notification_type: NotificationType::DataFeedStale,
                title: format!("Data Feed Stale: {}", status.feed_name),
                message: Some(format!(
                    "{}. Threshold: {} minutes",
                    staleness_detail, status.stale_threshold_minutes
                )),
                link: Some(format!("/log-sources/{}", status.feed_id)),
                metadata: serde_json::json!({
                    "feed_id": status.feed_id.to_string(),
                    "feed_name": status.feed_name,
                    "last_event_at": status.last_event_at,
                    "stale_threshold_minutes": status.stale_threshold_minutes,
                    "minutes_since_last_event": status.minutes_since_last_event,
                }),
            };

            if let Err(e) = self.notification_repo.create(&notification).await {
                warn!(
                    user_id = %user_id,
                    feed = %status.feed_name,
                    error = %e,
                    "Failed to create stale feed notification"
                );
            }
        }

        info!(
            feed = %status.feed_name,
            "Sent stale feed notifications to admin users"
        );

        Ok(())
    }

    /// Emit an audit event when a feed goes stale
    async fn emit_feed_stale_audit(&self, status: &super::types::FeedStalenessStatus) {
        let staleness_detail = status
            .minutes_since_last_event
            .map(|m| {
                if m >= 60 {
                    format!("No data received in {} hours", m / 60)
                } else {
                    format!("No data received in {} minutes", m)
                }
            })
            .unwrap_or_else(|| "No data has ever been received".to_string());

        let event = AuditEvent::builder(AuditSource::Ingest, "feed_stale")
            .resource(
                "log_source",
                Some(status.feed_id),
                Some(status.feed_name.clone()),
            )
            .success(false) // Staleness is a failure condition
            .details(serde_json::json!({
                "feed_id": status.feed_id.to_string(),
                "feed_name": status.feed_name,
                "last_event_at": status.last_event_at,
                "stale_threshold_minutes": status.stale_threshold_minutes,
                "minutes_since_last_event": status.minutes_since_last_event,
                "message": staleness_detail,
            }))
            .build();

        if let Err(e) = self.audit_emitter.emit(&event).await {
            warn!(
                feed = %status.feed_name,
                error = %e,
                "Failed to emit audit event for stale feed"
            );
        } else {
            debug!(
                feed = %status.feed_name,
                "Emitted audit event for stale feed"
            );
        }
    }
}
