// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rate Limiting for AI Detection Auto-Tuning
//!
//! Provides rate limiting and circuit breaker functionality to prevent:
//! - Excessive AI agent calls (max 10 concurrent)
//! - Too frequent auto-tuning per rule (max 1 per 24 hours)
//! - Cascading failures from AI agent errors

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;

/// Rate limiter for auto-tuning operations
#[derive(Clone)]
pub struct TuningRateLimiter {
    /// Semaphore for limiting concurrent AI agent calls
    ai_agent_semaphore: Arc<Semaphore>,
    /// PostgreSQL pool for querying/updating last_tuned_at on detection_rules
    pg_pool: Option<PgPool>,
    /// Circuit breaker state
    circuit_breaker: Arc<RwLock<CircuitBreakerState>>,
}

/// Circuit breaker state for AI agent calls
#[derive(Debug, Clone)]
struct CircuitBreakerState {
    /// Current state of the circuit breaker
    state: CircuitState,
    /// Number of consecutive failures
    failure_count: u32,
    /// Timestamp when circuit was opened
    opened_at: Option<DateTime<Utc>>,
    /// Timestamp of last failure
    last_failure_at: Option<DateTime<Utc>>,
}

/// Circuit breaker states
#[derive(Debug, Clone, PartialEq)]
enum CircuitState {
    /// Circuit is closed, requests flow normally
    Closed,
    /// Circuit is open, requests are rejected
    Open,
    /// Circuit is half-open, testing if service recovered
    HalfOpen,
}

impl Default for CircuitBreakerState {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            opened_at: None,
            last_failure_at: None,
        }
    }
}

/// Configuration for rate limiting
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Maximum concurrent AI agent calls
    pub max_concurrent_ai_calls: usize,
    /// Minimum time between tuning attempts for the same rule (in hours)
    pub min_tuning_interval_hours: i64,
    /// Number of failures before opening circuit
    pub circuit_breaker_threshold: u32,
    /// Time to wait before attempting to close circuit (in seconds)
    pub circuit_breaker_timeout_secs: i64,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            max_concurrent_ai_calls: 10,
            min_tuning_interval_hours: 24,
            circuit_breaker_threshold: 5,
            circuit_breaker_timeout_secs: 60,
        }
    }
}

impl TuningRateLimiter {
    /// Create a new rate limiter with default configuration (no DB, for tests)
    pub fn new() -> Self {
        Self::with_config(RateLimiterConfig::default())
    }

    /// Create a new rate limiter with custom configuration (no DB, for tests)
    pub fn with_config(config: RateLimiterConfig) -> Self {
        Self {
            ai_agent_semaphore: Arc::new(Semaphore::new(config.max_concurrent_ai_calls)),
            pg_pool: None,
            circuit_breaker: Arc::new(RwLock::new(CircuitBreakerState::default())),
        }
    }

    /// Create a new rate limiter backed by PostgreSQL for cross-node cooldown tracking
    pub fn with_pool(pool: PgPool) -> Self {
        Self {
            ai_agent_semaphore: Arc::new(Semaphore::new(
                RateLimiterConfig::default().max_concurrent_ai_calls,
            )),
            pg_pool: Some(pool),
            circuit_breaker: Arc::new(RwLock::new(CircuitBreakerState::default())),
        }
    }

    /// Fetch the `last_tuned_at` timestamp for a rule from PostgreSQL.
    ///
    /// Returns `None` when no pool is configured (test mode) or the rule
    /// has never been tuned.
    async fn get_last_tuned_at(&self, rule_id: Uuid) -> Option<DateTime<Utc>> {
        let pool = self.pg_pool.as_ref()?;
        let row: Option<(Option<DateTime<Utc>>,)> =
            sqlx::query_as("SELECT last_tuned_at FROM detection_rules WHERE id = $1")
                .bind(rule_id)
                .fetch_optional(pool)
                .await
                .unwrap_or(None);

        row.and_then(|(ts,)| ts)
    }

    /// Check if a rule can be tuned (respects 24-hour cooldown)
    ///
    /// When backed by PostgreSQL, queries the `last_tuned_at` column on
    /// `detection_rules`. Falls back to always-true when no pool is available.
    pub async fn can_tune_rule(&self, rule_id: Uuid) -> bool {
        match self.get_last_tuned_at(rule_id).await {
            Some(last_tuned_at) => {
                let elapsed = Utc::now().signed_duration_since(last_tuned_at);
                elapsed >= Duration::hours(24)
            }
            None => true,
        }
    }

    /// Record that a rule was tuned
    ///
    /// Updates the `last_tuned_at` timestamp in PostgreSQL when available.
    pub async fn record_tuning(&self, rule_id: Uuid) {
        if let Some(ref pool) = self.pg_pool {
            if let Err(e) =
                sqlx::query("UPDATE detection_rules SET last_tuned_at = NOW() WHERE id = $1")
                    .bind(rule_id)
                    .execute(pool)
                    .await
            {
                tracing::warn!("Failed to record tuning for rule {}: {}", rule_id, e);
            }
        }
    }

    /// Get time until a rule can be tuned again
    ///
    /// Returns None if the rule can be tuned now, or Some(duration) if it must wait.
    pub async fn time_until_can_tune(&self, rule_id: Uuid) -> Option<Duration> {
        let last_tuned_at = self.get_last_tuned_at(rule_id).await?;
        let elapsed = Utc::now().signed_duration_since(last_tuned_at);
        let required = Duration::hours(24);
        if elapsed < required {
            Some(required - elapsed)
        } else {
            None
        }
    }

    /// Acquire a permit for an AI agent call
    ///
    /// This will block until a permit is available or return an error if the
    /// circuit breaker is open.
    ///
    /// Returns a guard that releases the permit when dropped.
    pub async fn acquire_ai_permit(&self) -> Result<AiPermitGuard<'_>, RateLimitError> {
        // Check circuit breaker state
        {
            let mut breaker = self.circuit_breaker.write().await;

            match breaker.state {
                CircuitState::Open => {
                    // Check if timeout has elapsed
                    if let Some(opened_at) = breaker.opened_at {
                        let elapsed = Utc::now().signed_duration_since(opened_at);
                        if elapsed >= Duration::seconds(60) {
                            // Transition to half-open
                            breaker.state = CircuitState::HalfOpen;
                            tracing::info!("Circuit breaker transitioning to half-open state");
                        } else {
                            return Err(RateLimitError::CircuitBreakerOpen {
                                retry_after_secs: (Duration::seconds(60) - elapsed).num_seconds(),
                            });
                        }
                    }
                }
                CircuitState::HalfOpen => {
                    // Allow one request through to test
                    tracing::debug!("Circuit breaker in half-open state, allowing test request");
                }
                CircuitState::Closed => {
                    // Normal operation
                }
            }
        }

        // Acquire semaphore permit
        let permit = self
            .ai_agent_semaphore
            .acquire()
            .await
            .map_err(|_| RateLimitError::SemaphoreError)?;

        Ok(AiPermitGuard {
            _permit: permit,
            circuit_breaker: Arc::clone(&self.circuit_breaker),
        })
    }

    /// Record a successful AI agent call
    ///
    /// This resets the circuit breaker failure count.
    pub async fn record_ai_success(&self) {
        let mut breaker = self.circuit_breaker.write().await;

        match breaker.state {
            CircuitState::HalfOpen => {
                // Success in half-open state, close the circuit
                breaker.state = CircuitState::Closed;
                breaker.failure_count = 0;
                breaker.opened_at = None;
                tracing::info!("Circuit breaker closed after successful test");
            }
            CircuitState::Closed => {
                // Reset failure count on success
                if breaker.failure_count > 0 {
                    breaker.failure_count = 0;
                    tracing::debug!("Circuit breaker failure count reset");
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but handle gracefully
                tracing::warn!("Received success while circuit breaker is open");
            }
        }
    }

    /// Record a failed AI agent call
    ///
    /// This increments the failure count and may open the circuit breaker.
    pub async fn record_ai_failure(&self) {
        let mut breaker = self.circuit_breaker.write().await;

        breaker.failure_count += 1;
        breaker.last_failure_at = Some(Utc::now());

        match breaker.state {
            CircuitState::HalfOpen => {
                // Failure in half-open state, reopen the circuit
                breaker.state = CircuitState::Open;
                breaker.opened_at = Some(Utc::now());
                tracing::warn!("Circuit breaker reopened after failed test");
            }
            CircuitState::Closed => {
                // Check if we should open the circuit
                if breaker.failure_count >= 5 {
                    breaker.state = CircuitState::Open;
                    breaker.opened_at = Some(Utc::now());
                    tracing::error!(
                        "Circuit breaker opened after {} consecutive failures",
                        breaker.failure_count
                    );
                } else {
                    tracing::warn!(
                        "AI agent failure recorded ({}/{})",
                        breaker.failure_count,
                        5
                    );
                }
            }
            CircuitState::Open => {
                // Already open, just log
                tracing::debug!("Additional failure while circuit breaker is open");
            }
        }
    }

    /// Get circuit breaker status
    pub async fn get_circuit_status(&self) -> CircuitBreakerStatus {
        let breaker = self.circuit_breaker.read().await;

        CircuitBreakerStatus {
            is_open: breaker.state == CircuitState::Open,
            is_half_open: breaker.state == CircuitState::HalfOpen,
            failure_count: breaker.failure_count,
            opened_at: breaker.opened_at,
            last_failure_at: breaker.last_failure_at,
        }
    }

    /// Reset circuit breaker (for testing or manual intervention)
    pub async fn reset_circuit_breaker(&self) {
        let mut breaker = self.circuit_breaker.write().await;
        *breaker = CircuitBreakerState::default();
        tracing::info!("Circuit breaker manually reset");
    }

    /// Clear all rate limiting state (for testing)
    pub async fn clear_all(&self) {
        self.reset_circuit_breaker().await;
    }
}

impl Default for TuningRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard that releases an AI permit when dropped
pub struct AiPermitGuard<'a> {
    _permit: tokio::sync::SemaphorePermit<'a>,
    circuit_breaker: Arc<RwLock<CircuitBreakerState>>,
}

impl<'a> AiPermitGuard<'a> {
    /// Record success for this AI call
    pub async fn record_success(self) {
        let mut breaker = self.circuit_breaker.write().await;

        match breaker.state {
            CircuitState::HalfOpen => {
                breaker.state = CircuitState::Closed;
                breaker.failure_count = 0;
                breaker.opened_at = None;
                tracing::info!("Circuit breaker closed after successful test");
            }
            CircuitState::Closed => {
                if breaker.failure_count > 0 {
                    breaker.failure_count = 0;
                }
            }
            CircuitState::Open => {}
        }
    }

    /// Record failure for this AI call
    pub async fn record_failure(self) {
        let mut breaker = self.circuit_breaker.write().await;

        breaker.failure_count += 1;
        breaker.last_failure_at = Some(Utc::now());

        match breaker.state {
            CircuitState::HalfOpen => {
                breaker.state = CircuitState::Open;
                breaker.opened_at = Some(Utc::now());
                tracing::warn!("Circuit breaker reopened after failed test");
            }
            CircuitState::Closed => {
                if breaker.failure_count >= 5 {
                    breaker.state = CircuitState::Open;
                    breaker.opened_at = Some(Utc::now());
                    tracing::error!(
                        "Circuit breaker opened after {} consecutive failures",
                        breaker.failure_count
                    );
                }
            }
            CircuitState::Open => {}
        }
    }
}

/// Circuit breaker status information
#[derive(Debug, Clone)]
pub struct CircuitBreakerStatus {
    pub is_open: bool,
    pub is_half_open: bool,
    pub failure_count: u32,
    pub opened_at: Option<DateTime<Utc>>,
    pub last_failure_at: Option<DateTime<Utc>>,
}

/// Rate limiting errors
#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Circuit breaker is open, retry after {retry_after_secs} seconds")]
    CircuitBreakerOpen { retry_after_secs: i64 },

    #[error("Semaphore error")]
    SemaphoreError,

    #[error("Rule was tuned too recently, must wait {hours_remaining} hours")]
    RuleTunedTooRecently { hours_remaining: i64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_can_tune_rule_without_pool() {
        // Without a PgPool, all rules are always tunable (test/fallback mode)
        let limiter = TuningRateLimiter::new();
        let rule_id = Uuid::now_v7();

        // Should always return true without a pool
        assert!(limiter.can_tune_rule(rule_id).await);

        // Record tuning is a no-op without a pool
        limiter.record_tuning(rule_id).await;

        // Still true (no state persisted without pool)
        assert!(limiter.can_tune_rule(rule_id).await);
    }

    #[tokio::test]
    async fn test_ai_permit_acquisition() {
        let config = RateLimiterConfig {
            max_concurrent_ai_calls: 2,
            ..Default::default()
        };
        let limiter = TuningRateLimiter::with_config(config);

        // Acquire first permit
        let permit1 = limiter.acquire_ai_permit().await;
        assert!(permit1.is_ok());

        // Acquire second permit
        let permit2 = limiter.acquire_ai_permit().await;
        assert!(permit2.is_ok());

        // Third permit should block (we won't wait for it in this test)
        // Just verify we can create the future
        let _permit3_future = limiter.acquire_ai_permit();

        // Drop permits to release
        drop(permit1);
        drop(permit2);
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens() {
        let limiter = TuningRateLimiter::new();

        // Record failures
        for _ in 0..5 {
            limiter.record_ai_failure().await;
        }

        // Circuit should be open
        let status = limiter.get_circuit_status().await;
        assert!(status.is_open);
        assert_eq!(status.failure_count, 5);

        // Acquiring permit should fail
        let result = limiter.acquire_ai_permit().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_circuit_breaker_success_resets() {
        let limiter = TuningRateLimiter::new();

        // Record some failures
        limiter.record_ai_failure().await;
        limiter.record_ai_failure().await;

        let status = limiter.get_circuit_status().await;
        assert_eq!(status.failure_count, 2);

        // Record success
        limiter.record_ai_success().await;

        // Failure count should be reset
        let status = limiter.get_circuit_status().await;
        assert_eq!(status.failure_count, 0);
    }

    #[tokio::test]
    async fn test_circuit_breaker_reset() {
        let limiter = TuningRateLimiter::new();

        // Open the circuit
        for _ in 0..5 {
            limiter.record_ai_failure().await;
        }

        let status = limiter.get_circuit_status().await;
        assert!(status.is_open);

        // Reset
        limiter.reset_circuit_breaker().await;

        // Should be closed now
        let status = limiter.get_circuit_status().await;
        assert!(!status.is_open);
        assert_eq!(status.failure_count, 0);
    }

    #[tokio::test]
    async fn test_clear_all() {
        let limiter = TuningRateLimiter::new();

        // Record failures
        limiter.record_ai_failure().await;

        // Clear all
        limiter.clear_all().await;

        // Circuit should be reset
        let status = limiter.get_circuit_status().await;
        assert_eq!(status.failure_count, 0);
    }

    #[tokio::test]
    async fn test_permit_guard_success() {
        let limiter = TuningRateLimiter::new();

        // Record some failures first
        limiter.record_ai_failure().await;
        limiter.record_ai_failure().await;

        let status = limiter.get_circuit_status().await;
        assert_eq!(status.failure_count, 2);

        // Acquire permit and record success
        let permit = limiter.acquire_ai_permit().await.unwrap();
        permit.record_success().await;

        // Failure count should be reset
        let status = limiter.get_circuit_status().await;
        assert_eq!(status.failure_count, 0);
    }

    #[tokio::test]
    async fn test_permit_guard_failure() {
        let limiter = TuningRateLimiter::new();

        // Acquire permit and record failure
        let permit = limiter.acquire_ai_permit().await.unwrap();
        permit.record_failure().await;

        // Failure count should be incremented
        let status = limiter.get_circuit_status().await;
        assert_eq!(status.failure_count, 1);
    }
}
