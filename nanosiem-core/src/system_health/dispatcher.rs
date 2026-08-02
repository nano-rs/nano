// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{sync::Arc, time::Duration};

use tracing::{error, info, warn};

use crate::webhooks::{WebhookPayload, WebhookRepository, WebhookService};

use super::{SystemHealthError, SystemHealthRepository, SYSTEM_HEALTH_EVENT_TYPE};

#[derive(Clone)]
pub struct SystemHealthDispatcher {
    repository: SystemHealthRepository,
    webhook_service: WebhookService,
    worker_id: String,
}

impl SystemHealthDispatcher {
    pub fn new(repository: SystemHealthRepository, worker_id: impl Into<String>) -> Self {
        let webhook_service = WebhookService::new(WebhookRepository::new(repository.pool()));
        Self {
            repository,
            webhook_service,
            worker_id: worker_id.into(),
        }
    }

    pub fn start(self: Arc<Self>, poll_interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let poll_interval = poll_interval.max(Duration::from_secs(1));
            info!(?poll_interval, "System health delivery dispatcher started");
            loop {
                match self.drain(32).await {
                    Ok(0) => tokio::time::sleep(poll_interval).await,
                    Ok(processed) => {
                        tracing::debug!(processed, "Drained system health delivery batch")
                    }
                    Err(error) => {
                        error!(%error, "System health delivery dispatcher failed");
                        tokio::time::sleep(poll_interval).await;
                    }
                }
            }
        })
    }

    pub async fn drain(&self, max: usize) -> Result<usize, SystemHealthError> {
        let mut deliveries = Vec::with_capacity(max);
        for _ in 0..max {
            let Some(delivery) = self.repository.claim_delivery(&self.worker_id).await? else {
                break;
            };
            deliveries.push(delivery);
        }

        let processed = deliveries.len();
        // A black-hole endpoint can consume the full HTTP timeout/retry window.
        // Polling rows sequentially would head-of-line block unrelated owners;
        // the existing WebhookService semaphore keeps this fanout bounded.
        for result in futures::future::join_all(
            deliveries
                .into_iter()
                .map(|delivery| self.dispatch_one(delivery)),
        )
        .await
        {
            result?;
        }
        Ok(processed)
    }

    async fn dispatch_one(
        &self,
        delivery: super::ClaimedHealthDelivery,
    ) -> Result<(), SystemHealthError> {
        let event = match self.repository.get(delivery.event_id).await {
            Ok(event) => event,
            Err(error) => {
                self.repository
                    .finish_delivery(&delivery, false, None, Some(&error.to_string()))
                    .await?;
                return Ok(());
            }
        };
        let base = self.webhook_service.resolve_base_url().await;
        // Snapshot the lifecycle transition from the outbox row. The event
        // itself may already be resolved by the time its trigger is
        // dispatched; rendering from current state would turn that queued
        // trigger into an out-of-order recovery notification.
        let is_resolution = delivery.event_action == "resolved";
        let payload = WebhookPayload {
            event_type: format!("system_health.{}", delivery.event_action),
            kind: Some(SYSTEM_HEALTH_EVENT_TYPE.to_string()),
            alert_id: None,
            rule_id: None,
            rule_name: Some(if is_resolution {
                format!("Resolved: {}", event.title)
            } else {
                event.title.clone()
            }),
            severity: Some(if is_resolution {
                "informational".to_string()
            } else {
                event.severity.clone()
            }),
            entity: event
                .resource_name
                .clone()
                .or_else(|| event.resource_id.clone()),
            link_url: WebhookService::ui_link_public(base.as_deref(), "platform/health"),
            matched_event_count: Some(event.occurrence_count),
            matched_events: None,
            created_at: if is_resolution {
                event.resolved_at.unwrap_or(event.last_seen_at)
            } else {
                event.first_seen_at
            },
            health_event_id: Some(event.id),
            health_status: Some(if is_resolution {
                "resolved".to_string()
            } else {
                "active".to_string()
            }),
            health_category: Some(event.category.clone()),
            health_resource_type: Some(event.resource_type.clone()),
            health_resource_id: event.resource_id.clone(),
            health_summary: Some(event.summary.clone()),
            health_diagnostic_context: Some(event.diagnostic_context.clone()),
            health_remediation: event.remediation.clone(),
            idempotency_key: Some(format!("{}:{}", event.id, delivery.event_action)),
        };

        match self
            .webhook_service
            .deliver_persisted(
                delivery.webhook_id,
                &payload,
                SYSTEM_HEALTH_EVENT_TYPE,
                &payload.event_type,
            )
            .await
        {
            Ok(result) => {
                self.repository
                    .finish_delivery(
                        &delivery,
                        result.success,
                        result.status_code.map(i32::from),
                        result.error.as_deref(),
                    )
                    .await?;
                if !result.success {
                    warn!(
                        event_id = %event.id,
                        webhook_id = %delivery.webhook_id,
                        attempt = delivery.attempt_count,
                        error = ?result.error,
                        "System health delivery will retry"
                    );
                }
            }
            Err(error) => {
                self.repository
                    .finish_delivery(&delivery, false, None, Some(&error))
                    .await?;
                warn!(
                    event_id = %event.id,
                    webhook_id = %delivery.webhook_id,
                    attempt = delivery.attempt_count,
                    %error,
                    "System health delivery setup failed"
                );
            }
        }
        Ok(())
    }
}
