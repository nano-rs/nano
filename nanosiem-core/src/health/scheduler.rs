// SPDX-License-Identifier: AGPL-3.0-or-later

//! Health monitoring scheduler
//!
//! Background task that periodically checks AI provider and feed health,
//! creates notifications for issues, and tracks issue resolution.

use sqlx::PgPool;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use crate::audit::{AuditEmitter, AuditEvent, AuditSource};
use crate::db::DualPool;
use crate::models::notification::NotificationType;
use crate::system_health::{
    HealthCategory, HealthSeverity, PublishHealthEvent, SystemHealthRepository,
};

use super::ai_monitor::{AiMonitor, AiProviderConnectivityChecker};
use super::disk_monitor::{self, DiskComponent, DiskLevel, DiskVolumeHealth};
use super::feed_monitor::FeedMonitor;
use super::repository::{HealthNotification, HealthRepository};
use super::stuck_query_monitor::StuckQueryMonitor;
use super::types::{HealthIssueType, HealthSchedulerConfig};

/// Health monitoring scheduler
pub struct HealthScheduler {
    config: HealthSchedulerConfig,
    health_repo: HealthRepository,
    ai_monitor: AiMonitor,
    feed_monitor: FeedMonitor,
    stuck_query_monitor: StuckQueryMonitor,
    audit_emitter: AuditEmitter,
    system_health_repo: SystemHealthRepository,
    /// NAN-5450: disk usage probes (ClickHouse, PostgreSQL, Vector buffers).
    dual_pool: DualPool,
}

impl HealthScheduler {
    /// Create a new scheduler with DualPool support.
    ///
    /// `ai_checker` is the injected, on-prem-`base_url`-aware provider
    /// connectivity test (NAN-1231); `None` skips AI-provider health checks
    /// (open-core / no AI surface). `airgap` skips probing any provider without
    /// an on-prem `base_url` so the monitor never beacons to a public host.
    pub fn with_dual_pool(
        pool: PgPool,
        dual_pool: DualPool,
        config: HealthSchedulerConfig,
        ai_checker: Option<Arc<dyn AiProviderConnectivityChecker>>,
        airgap: bool,
    ) -> Self {
        let stuck_query_monitor = StuckQueryMonitor::new(
            dual_pool.clickhouse().clone(),
            config.stuck_query_threshold_secs,
        );
        Self {
            config,
            health_repo: HealthRepository::new(pool.clone()),
            system_health_repo: SystemHealthRepository::new(pool.clone()),
            ai_monitor: AiMonitor::new(pool.clone(), ai_checker, airgap),
            feed_monitor: FeedMonitor::with_clickhouse(pool, dual_pool.clickhouse().clone()),
            stuck_query_monitor,
            audit_emitter: AuditEmitter::new(dual_pool.clone()),
            dual_pool,
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

        // Stuck-query check has no settings gate: it is one lightweight
        // system-table probe per cycle, and the failure mode it detects (a
        // permanently wedged 100%-CPU ClickHouse thread, NAN-2274 /
        // ClickHouse#113003) has no other signal anywhere in the product.
        if let Err(e) = self.check_stuck_queries().await {
            error!(error = %e, "Failed to check for stuck ClickHouse queries");
        }

        // NAN-5450: no settings gate either. PostgreSQL and the Vector
        // buffers have no other in-app disk signal, and a full PostgreSQL
        // stops the jobs leader (and with it the disk-pressure evictor).
        if let Err(e) = self.check_disk_usage().await {
            error!(error = %e, "Failed to check disk usage");
        }
    }

    /// NAN-5450: tiered disk escalation, per underlying disk (a volume that
    /// shares another's filesystem, single-host PostgreSQL on the ClickHouse
    /// disk, is covered by that disk and skipped).
    ///
    /// * 80 %: one in-app notification to admins and a system-health event
    ///   (SIEM Health and Settings -> Storage show it too).
    /// * 90 %, or forecast to fill within 24 hours: one more notification,
    ///   and the event escalates to High, which re-notifies the configured
    ///   channels (email, Slack, webhook, PagerDuty) once. The ClickHouse disk
    ///   already has the disk-pressure service's event and 90 % notification,
    ///   so for it this adds the 80 % notification and the forecast escalation.
    /// * 95 % (imminent): a Critical event of its own that notifies the
    ///   channels, then repeats to the channels and to admins every hour
    ///   while it lasts ([`IMMINENT_REMINDER_EVERY`]).
    ///
    /// Each cycle also records a usage sample per disk for the forecast.
    async fn check_disk_usage(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let report = disk_monitor::collect_from_dual_pool(&self.dual_pool).await;
        if let Err(e) = disk_monitor::record_samples(self.dual_pool.postgres(), &report).await {
            warn!(error = %e, "Failed to record disk usage samples (no forecast until they are)");
        }
        let issue_type = HealthIssueType::DiskUsage.to_string();
        // NAN-5450 review: the ClickHouse disk warns above the evictor's high
        // watermark, so its resolve point (hysteresis) follows that level and
        // a capped install cycling 70-80 % neither warns nor re-arms.
        let band = disk_monitor::EvictorBand::from_env();
        for volume in report.volumes.iter().filter(|v| v.shared_with.is_none()) {
            let forecast_escalated = volume.forecast.as_ref().is_some_and(|f| f.escalated);
            for (step, threshold) in [
                (DiskLevel::Warning, disk_monitor::warn_fraction_for(volume.component, &band)),
                (DiskLevel::Critical, disk_monitor::DISK_CRITICAL_FRACTION),
                (DiskLevel::Imminent, disk_monitor::DISK_IMMINENT_FRACTION),
            ] {
                let issue_key = Self::disk_issue_key(volume, step);
                match disk_step_action(volume, step, threshold) {
                    DiskStepAction::Notify => {
                        if volume.component == DiskComponent::Clickhouse
                            && step == DiskLevel::Critical
                            && !forecast_escalated
                        {
                            continue;
                        }
                        let notification = Self::disk_notification(volume, step);
                        if let Some(recipients) = self
                            .health_repo
                            .notify_issue_once(&issue_type, &issue_key, &notification)
                            .await?
                        {
                            info!(volume = %volume.key(), level = step.as_str(), recipients,
                                "Sent disk usage notifications to admin users");
                        }
                    }
                    DiskStepAction::Resolve => {
                        self.health_repo.resolve_issue(&issue_type, &issue_key).await?;
                    }
                    DiskStepAction::Hold => {}
                }
            }

            // The per-volume event (80 % / 90 %). For ClickHouse only when the
            // forecast escalated it: the disk-pressure event covers the rest.
            if volume.component != DiskComponent::Clickhouse || forecast_escalated {
                let dedup = Self::disk_dedup_key(volume);
                match volume.level {
                    DiskLevel::Warning | DiskLevel::Critical | DiskLevel::Imminent => {
                        if let Err(error) = self.system_health_repo.publish(&Self::disk_health_event(volume)).await {
                            warn!(volume = %volume.key(), %error, "Failed to publish disk usage system health event");
                        }
                    }
                    DiskLevel::Ok => {
                        if let Err(error) = self.system_health_repo.resolve_by_dedup_key(&dedup).await {
                            warn!(volume = %volume.key(), %error, "Failed to resolve disk usage system health event");
                        }
                    }
                    DiskLevel::Unknown => {}
                }
            } else if volume.level != DiskLevel::Unknown {
                let _ = self.system_health_repo.resolve_by_dedup_key(&Self::disk_dedup_key(volume)).await;
            }

            // Imminent: its own Critical event, repeated hourly.
            let imminent_dedup = Self::disk_imminent_dedup_key(volume);
            match disk_step_action(volume, DiskLevel::Imminent, disk_monitor::DISK_IMMINENT_FRACTION) {
                DiskStepAction::Notify => {
                    if let Err(error) = self.system_health_repo.publish(&Self::disk_imminent_event(volume)).await {
                        warn!(volume = %volume.key(), %error, "Failed to publish imminent disk event");
                        continue;
                    }
                    match self.system_health_repo.remind_if_due(&imminent_dedup, IMMINENT_REMINDER_EVERY).await {
                        Ok(true) => {
                            let notification = Self::disk_notification(volume, DiskLevel::Imminent);
                            match self.health_repo.notify_admins(&notification).await {
                                Ok(recipients) => info!(volume = %volume.key(), recipients,
                                    "Repeated the imminent disk notification (hourly)"),
                                Err(error) => warn!(volume = %volume.key(), %error,
                                    "Failed to repeat the imminent disk notification"),
                            }
                        }
                        Ok(false) => {}
                        Err(error) => warn!(volume = %volume.key(), %error, "Failed to schedule the imminent disk reminder"),
                    }
                }
                DiskStepAction::Resolve => {
                    if let Err(error) = self.system_health_repo.resolve_by_dedup_key(&imminent_dedup).await {
                        warn!(volume = %volume.key(), %error, "Failed to resolve imminent disk event");
                    }
                }
                DiskStepAction::Hold => {}
            }
        }
        Ok(())
    }

    fn disk_imminent_dedup_key(volume: &DiskVolumeHealth) -> String {
        format!("storage:disk:imminent:{}", volume.key())
    }

    fn disk_imminent_event(volume: &DiskVolumeHealth) -> PublishHealthEvent {
        let mut event = Self::disk_health_event(volume);
        event.dedup_key = Self::disk_imminent_dedup_key(volume);
        event.severity = HealthSeverity::Critical;
        event.title = format!("{} is about to fill", volume.display_name());
        event.summary = format!(
            "{}. {}",
            volume.detail,
            "Ingest will pause and the oldest data will be dropped; PostgreSQL stops if its disk fills."
        );
        event
    }

    fn disk_issue_key(volume: &DiskVolumeHealth, step: DiskLevel) -> String {
        let mut key = format!("{}:{}", volume.key(), step.as_str());
        // health_issue_tracker.issue_key is VARCHAR(255).
        if key.len() > 255 {
            let mut cut = 255;
            while !key.is_char_boundary(cut) {
                cut -= 1;
            }
            key.truncate(cut);
        }
        key
    }

    fn disk_dedup_key(volume: &DiskVolumeHealth) -> String {
        format!("storage:disk:{}", volume.key())
    }

    fn disk_notification(volume: &DiskVolumeHealth, step: DiskLevel) -> HealthNotification {
        let pct = volume
            .usage_fraction
            .map(|f| format!("{:.1}%", f * 100.0))
            .unwrap_or_else(|| "unknown".into());
        let what = match step {
            DiskLevel::Imminent => "about to fill",
            DiskLevel::Critical if volume.forecast.as_ref().is_some_and(|f| f.escalated) => "filling fast",
            DiskLevel::Critical => "critically full",
            _ => "filling up",
        };
        HealthNotification {
            notification_type: NotificationType::DiskPressureWarning,
            title: format!("{} {what}: {pct}", volume.display_name()),
            message: Some(format!(
                "{}: {}. {}",
                volume.display_name(),
                volume.detail,
                disk_remediation(volume.component)
            )),
            link: Some("/settings/storage".to_string()),
            metadata: serde_json::json!({
                "component": volume.component.as_str(),
                "host": volume.host,
                "name": volume.name,
                "usage_fraction": volume.usage_fraction,
                "level": step.as_str(),
            }),
        }
    }

    fn disk_health_event(volume: &DiskVolumeHealth) -> PublishHealthEvent {
        let severity = if volume.level >= DiskLevel::Critical {
            HealthSeverity::High
        } else {
            HealthSeverity::Medium
        };
        let mut event = PublishHealthEvent::new(
            Self::disk_dedup_key(volume),
            HealthCategory::Storage,
            severity,
            format!("{} is {}", volume.display_name(), volume.level.as_str()),
            volume.detail.clone(),
            volume.component.as_str(),
            "health_scheduler.disk_monitor",
        );
        event.resource_id = Some(volume.key());
        event.resource_name = Some(volume.display_name());
        event.diagnostic_context = serde_json::json!({
            "total_bytes": volume.total_bytes,
            "used_bytes": volume.used_bytes,
            "free_bytes": volume.free_bytes,
            "usage_fraction": volume.usage_fraction,
            "forecast": volume.forecast,
        });
        event.remediation = Some(disk_remediation(volume.component).to_string());
        event
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
                let notification = Self::ai_provider_notification(&status);
                if let Some(recipients) = self
                    .health_repo
                    .notify_issue_once(
                        &HealthIssueType::AiProvider.to_string(),
                        &issue_key,
                        &notification,
                    )
                    .await?
                {
                    if recipients == 0 {
                        warn!("No admin users found to notify about AI provider issue");
                    } else {
                        info!(
                            provider = %status.provider_name,
                            recipients,
                            "Sent AI provider down notifications to admin users"
                        );
                    }
                }
                let event = Self::ai_provider_health_event(&status);
                if let Err(error) = self.system_health_repo.publish(&event).await {
                    warn!(
                        provider = %status.provider_type,
                        %error,
                        "Failed to publish AI-provider system health event"
                    );
                }
            } else {
                // Provider is healthy - resolve any existing issue
                self.health_repo
                    .resolve_issue(&HealthIssueType::AiProvider.to_string(), &issue_key)
                    .await?;
                if let Err(error) = self
                    .system_health_repo
                    .resolve_by_dedup_key(&Self::ai_provider_dedup_key(&status.provider_type))
                    .await
                {
                    warn!(
                        provider = %status.provider_type,
                        %error,
                        "Failed to resolve AI-provider system health event"
                    );
                }
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
                let notification = Self::feed_stale_notification(&status);
                if let Some(recipients) = self
                    .health_repo
                    .notify_issue_once(
                        &HealthIssueType::DataFeed.to_string(),
                        &issue_key,
                        &notification,
                    )
                    .await?
                {
                    if recipients == 0 {
                        warn!("No admin users found to notify about stale feed");
                    } else {
                        info!(
                            feed = %status.feed_name,
                            recipients,
                            "Sent stale feed notifications to admin users"
                        );
                    }
                    self.emit_feed_stale_audit(&status).await;
                }

                // NAN-2282: adapt the EXISTING staleness detector into the
                // normalized bus. This deliberately does not add another
                // ClickHouse probe or replace the current in-app notification.
                let event = Self::feed_stale_health_event(&status);
                if let Err(error) = self.system_health_repo.publish(&event).await {
                    warn!(
                        feed_id = %status.feed_id,
                        %error,
                        "Failed to publish stale-feed system health event"
                    );
                }
            } else {
                // Feed is healthy - resolve any existing issue
                self.health_repo
                    .resolve_issue(&HealthIssueType::DataFeed.to_string(), &issue_key)
                    .await?;
                if let Err(error) = self
                    .system_health_repo
                    .resolve_by_dedup_key(&Self::feed_stale_dedup_key(status.feed_id))
                    .await
                {
                    warn!(
                        feed_id = %status.feed_id,
                        %error,
                        "Failed to resolve stale-feed system health event"
                    );
                }
            }
        }

        Ok(())
    }

    /// Report cancelled-but-still-running ClickHouse queries and resolve the
    /// ones that have disappeared (thread cleared by a server restart).
    async fn check_stuck_queries(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let probe = self.stuck_query_monitor.check_stuck_queries().await;

        let current: std::collections::HashSet<&str> =
            probe.statuses.iter().map(|s| s.query_id.as_str()).collect();

        for status in &probe.statuses {
            let notification = Self::stuck_query_notification(status);
            if let Some(recipients) = self
                .health_repo
                .notify_issue_once(
                    &HealthIssueType::StuckQuery.to_string(),
                    &status.query_id,
                    &notification,
                )
                .await?
            {
                if recipients == 0 {
                    warn!("No admin users found to notify about stuck ClickHouse query");
                } else {
                    info!(
                        query_id = %status.query_id,
                        elapsed_secs = status.elapsed_secs,
                        recipients,
                        "Sent stuck ClickHouse query notifications to admin users"
                    );
                }
            }

            let event = Self::stuck_query_health_event(status);
            if let Err(error) = self.system_health_repo.publish(&event).await {
                warn!(
                    query_id = %status.query_id,
                    %error,
                    "Failed to publish stuck-query system health event"
                );
            }
        }

        // A tracked stuck query that is no longer in system.processes means the
        // server was restarted (the only way the thread clears) — resolve it.
        // Only an authoritative probe may resolve: an errored or
        // degraded-to-local view returning nothing would otherwise resolve
        // every tracked issue, re-arm notify_issue_once, and re-notify the
        // same wedge on every probe flap.
        if !probe.authoritative {
            return Ok(());
        }
        for issue in self.health_repo.list_active_issues().await? {
            if issue.issue_type == HealthIssueType::StuckQuery.to_string()
                && !current.contains(issue.issue_key.as_str())
            {
                self.health_repo
                    .resolve_issue(&issue.issue_type, &issue.issue_key)
                    .await?;
                if let Err(error) = self
                    .system_health_repo
                    .resolve_by_dedup_key(&Self::stuck_query_dedup_key(&issue.issue_key))
                    .await
                {
                    warn!(
                        query_id = %issue.issue_key,
                        %error,
                        "Failed to resolve stuck-query system health event"
                    );
                }
            }
        }

        Ok(())
    }

    fn ai_provider_notification(status: &super::types::AiProviderStatus) -> HealthNotification {
        let error_detail = status
            .error_message
            .as_ref()
            .map(|e| format!(": {}", e))
            .unwrap_or_default();

        HealthNotification {
            notification_type: NotificationType::AiProviderDown,
            title: format!("AI Provider Down: {}", status.provider_name),
            message: Some(format!(
                "The {} AI provider is not responding{}",
                status.provider_name, error_detail
            )),
            link: Some("/settings/ai".to_string()),
            metadata: serde_json::json!({
                "provider_type": status.provider_type,
                "provider_name": status.provider_name,
                "error_message": status.error_message,
            }),
        }
    }

    fn ai_provider_health_event(status: &super::types::AiProviderStatus) -> PublishHealthEvent {
        let mut event = PublishHealthEvent::new(
            Self::ai_provider_dedup_key(&status.provider_type),
            HealthCategory::Service,
            HealthSeverity::High,
            format!("AI provider unavailable: {}", status.provider_name),
            status
                .error_message
                .clone()
                .unwrap_or_else(|| "The provider connectivity check failed.".to_string()),
            "ai_provider",
            "health_scheduler.ai_monitor",
        );
        event.resource_id = Some(status.provider_type.clone());
        event.resource_name = Some(status.provider_name.clone());
        event.diagnostic_context = serde_json::json!({
            "provider_type": status.provider_type,
            "checked_at": status.checked_at,
            "error_message": status.error_message,
        });
        event.remediation = Some(
            "Verify the provider credential, API endpoint, account quota, network egress, and provider status."
                .to_string(),
        );
        event
    }

    fn ai_provider_dedup_key(provider_type: &str) -> String {
        format!("service:ai_provider:{provider_type}:unavailable")
    }

    fn stuck_query_notification(status: &super::types::StuckQueryStatus) -> HealthNotification {
        let elapsed = if status.elapsed_secs >= 3600.0 {
            format!("{:.1} hours", status.elapsed_secs / 3600.0)
        } else {
            format!("{:.0} minutes", status.elapsed_secs / 60.0)
        };

        HealthNotification {
            notification_type: NotificationType::StuckQueryDetected,
            title: "Unkillable ClickHouse query detected".to_string(),
            message: Some(format!(
                "Query {} (user: {}) was cancelled but has been running for {}. \
                 It is stuck in query planning, is holding a CPU core at 100%, and \
                 will not stop on its own — restarting the ClickHouse server is the \
                 only way to clear it.",
                status.query_id, status.user, elapsed
            )),
            link: None,
            metadata: serde_json::json!({
                "query_id": status.query_id,
                "user": status.user,
                "elapsed_secs": status.elapsed_secs,
                "query_snippet": status.query_snippet,
            }),
        }
    }

    fn stuck_query_health_event(status: &super::types::StuckQueryStatus) -> PublishHealthEvent {
        let mut event = PublishHealthEvent::new(
            Self::stuck_query_dedup_key(&status.query_id),
            HealthCategory::Query,
            HealthSeverity::High,
            "Unkillable ClickHouse query detected",
            format!(
                "Query {} has remained active for {:.0} seconds after cancellation and is holding a CPU core.",
                status.query_id, status.elapsed_secs
            ),
            "clickhouse_query",
            "health_scheduler.stuck_query_monitor",
        );
        event.resource_id = Some(status.query_id.clone());
        event.resource_name = Some(status.user.clone());
        event.diagnostic_context = serde_json::json!({
            "query_id": status.query_id,
            "user": status.user,
            "elapsed_secs": status.elapsed_secs,
            "query_snippet": status.query_snippet,
        });
        event.remediation = Some(
            "Restart the affected ClickHouse server to clear the wedged query-planning thread."
                .to_string(),
        );
        event
    }

    fn stuck_query_dedup_key(query_id: &str) -> String {
        format!("query:{query_id}:stuck")
    }

    fn feed_stale_notification(status: &super::types::FeedStalenessStatus) -> HealthNotification {
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

        HealthNotification {
            notification_type: NotificationType::DataFeedStale,
            title: format!("Data Feed Stale: {}", status.feed_name),
            message: Some(format!(
                "{}. Threshold: {} minutes",
                staleness_detail, status.stale_threshold_minutes
            )),
            // NAN-1933: target the real /ingestion/log-sources/<typeid> route.
            // feed_id is log_sources.id (a Uuid); encode it as the `lsrc` typeid
            // the route resolves — Display would emit a raw UUID that 404s.
            link: Some(format!(
                "/ingestion/log-sources/{}",
                crate::typeid::encode(crate::typeid::log_source::PREFIX, &status.feed_id)
            )),
            metadata: serde_json::json!({
                "feed_id": status.feed_id.to_string(),
                "feed_name": status.feed_name,
                "last_event_at": status.last_event_at,
                "stale_threshold_minutes": status.stale_threshold_minutes,
                "minutes_since_last_event": status.minutes_since_last_event,
            }),
        }
    }

    fn feed_stale_health_event(status: &super::types::FeedStalenessStatus) -> PublishHealthEvent {
        let staleness_detail = status
            .minutes_since_last_event
            .map(|minutes| format!("No data received for {minutes} minutes"))
            .unwrap_or_else(|| "No data has ever been received".to_string());
        let mut event = PublishHealthEvent::new(
            Self::feed_stale_dedup_key(status.feed_id),
            HealthCategory::LogSource,
            HealthSeverity::High,
            format!("Log source stopped sending: {}", status.feed_name),
            format!(
                "{staleness_detail}; configured stale threshold is {} minutes.",
                status.stale_threshold_minutes
            ),
            "log_source",
            "health_scheduler.feed_monitor",
        );
        event.resource_id = Some(status.feed_id.to_string());
        event.resource_name = Some(status.feed_name.clone());
        event.diagnostic_context = serde_json::json!({
            "last_event_at": status.last_event_at,
            "minutes_since_last_event": status.minutes_since_last_event,
            "stale_threshold_minutes": status.stale_threshold_minutes,
        });
        event.remediation = Some(
            "Check the upstream sender, credentials, network path, parser routing, and recent source configuration changes."
                .to_string(),
        );
        event
    }

    /// Stable identity shared by the stale producer and healthy recovery path.
    fn feed_stale_dedup_key(feed_id: uuid::Uuid) -> String {
        format!("log_source:{feed_id}:stale")
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

/// NAN-5450: how often an imminent disk re-notifies channels and admins.
pub(crate) const IMMINENT_REMINDER_EVERY: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// What one threshold step does for one volume this cycle.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DiskStepAction {
    Notify,
    Resolve,
    Hold,
}

/// Hysteresis: a step resolves only 5 points below its threshold, so a volume
/// hovering at 80 % does not notify on every cycle. Unknown usage holds (a
/// failed probe must not resolve and re-arm the notification).
const DISK_RESOLVE_MARGIN: f64 = 0.05;

pub(crate) fn disk_step_action(volume: &DiskVolumeHealth, step: DiskLevel, threshold: f64) -> DiskStepAction {
    match volume.usage_fraction {
        _ if volume.level == DiskLevel::Unknown => DiskStepAction::Hold,
        Some(_) if volume.level >= step => DiskStepAction::Notify,
        Some(f) if f < threshold - DISK_RESOLVE_MARGIN => DiskStepAction::Resolve,
        _ => DiskStepAction::Hold,
    }
}

fn disk_remediation(component: DiskComponent) -> &'static str {
    match component {
        DiskComponent::Clickhouse => {
            "Free space or grow the disk. The disk-pressure service drops the oldest partitions above its \
             high watermark; see docs/administration/disk-full-recovery.md."
        }
        DiskComponent::Postgres => {
            "Free space or grow the PostgreSQL volume before it fills: a full WAL disk stops PostgreSQL and \
             every nano service with it. See docs/administration/disk-full-recovery.md."
        }
        DiskComponent::VectorBuffer => {
            "Vector is holding events it cannot deliver, usually because ClickHouse refuses writes. A full \
             buffer pushes back on senders. Check ClickHouse health and disk space."
        }
    }
}

#[cfg(test)]
#[path = "scheduler_tests.rs"]
mod tests;
