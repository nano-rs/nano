// SPDX-License-Identifier: AGPL-3.0-or-later

//! API configuration

use std::env;

/// Deployment mode — managed (platform-hosted) vs self-hosted (BYOC) vs demo
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentMode {
    /// Platform-managed: AI pre-configured, settings locked
    Managed,
    /// Self-hosted / BYOC: user manages everything
    SelfHosted,
    /// Demo: shared instance with session-scoped ephemeral users
    Demo,
}

impl DeploymentMode {
    pub fn is_managed(&self) -> bool {
        matches!(self, DeploymentMode::Managed)
    }

    pub fn is_demo(&self) -> bool {
        matches!(self, DeploymentMode::Demo)
    }
}

/// Configuration for the API server
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Host to bind to
    pub host: String,
    /// Port to listen on
    pub port: u16,
    /// Database URL
    pub database_url: String,
    /// CORS allowed origins (comma-separated)
    pub cors_origins: Vec<String>,
    /// Enable authentication (optional)
    pub auth_enabled: bool,
    /// API key for authentication (if enabled)
    pub api_key: Option<String>,
    /// Deployment mode
    pub deployment_mode: DeploymentMode,
    /// Demo session TTL in hours (only used when deployment_mode = Demo)
    pub demo_session_ttl_hours: i64,
    /// Maximum demo sessions per IP per hour (rate limiting)
    pub demo_max_sessions_per_ip: u32,
    /// License API URL for BYOC enforcement (e.g. https://api.nano.rs/api/license/status)
    /// Reads LICENSE_URL (preferred) or HEARTBEAT_URL (legacy) env var.
    pub license_url: Option<String>,
    /// Bearer token for license API authentication
    /// Reads LICENSE_TOKEN (preferred) or HEARTBEAT_TOKEN (legacy) env var.
    pub license_token: Option<String>,
    /// Unique deployment identifier assigned by nano-main
    pub deployment_id: Option<String>,
    /// Air-gapped install: no outbound internet. Orthogonal to `deployment_mode`
    /// (an air-gap install is still self-hosted), so it's a separate flag rather
    /// than a 4th `DeploymentMode` variant. Read from `AIRGAP_MODE` ("1"/"true").
    /// When true, marketplace egress paths (deno/native/identity sync, GitHub
    /// repo sync) refuse cleanly instead of attempting a doomed fetch — bundles
    /// come in via the air-gap import surface instead.
    pub airgap: bool,
}

impl ApiConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let cors_origins = env::var("CORS_ORIGINS")
            .unwrap_or_else(|_| "*".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        Self {
            host: env::var("API_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("API_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3000),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/nanosiem".to_string()),
            cors_origins,
            auth_enabled: env::var("AUTH_ENABLED")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            api_key: env::var("API_KEY").ok(),
            deployment_mode: match env::var("DEPLOYMENT_MODE").as_deref() {
                Ok("managed") => DeploymentMode::Managed,
                Ok("demo") => DeploymentMode::Demo,
                _ => DeploymentMode::SelfHosted,
            },
            demo_session_ttl_hours: env::var("DEMO_SESSION_TTL_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(72), // 3 days
            demo_max_sessions_per_ip: env::var("DEMO_MAX_SESSIONS_PER_IP")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            license_url: env::var("LICENSE_URL")
                .ok()
                .or_else(|| env::var("HEARTBEAT_URL").ok()),
            license_token: env::var("LICENSE_TOKEN")
                .ok()
                .or_else(|| env::var("HEARTBEAT_TOKEN").ok()),
            deployment_id: env::var("NANO_DEPLOYMENT_ID").ok(),
            airgap: env::var("AIRGAP_MODE")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
        }
    }

    /// Get the bind address
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Returns true if license enforcement is configured.
    /// Requires LICENSE_URL (or HEARTBEAT_URL), LICENSE_TOKEN (or HEARTBEAT_TOKEN),
    /// and NANO_DEPLOYMENT_ID.
    pub fn is_license_enabled(&self) -> bool {
        self.license_url.is_some() && self.license_token.is_some() && self.deployment_id.is_some()
    }

    /// Whether background jobs that make outbound network calls (IPinfo
    /// enrichment, identity sync, GitHub repo auto-sync, marketplace, model
    /// catalog, remote inputlookup ingestion) are allowed to start.
    ///
    /// Air-gapped installs have no outbound internet, so these egress jobs are
    /// skipped at their spawn sites — content arrives via the air-gap import
    /// surface instead. Internal jobs (detection, tuning, cleanups) are
    /// unaffected by this predicate.
    pub fn egress_jobs_enabled(&self) -> bool {
        !self.airgap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_jobs_enabled_by_default() {
        // Connected / non-air-gap self-hosted: egress jobs run.
        let config = ApiConfig::default();
        assert!(!config.airgap);
        assert!(config.egress_jobs_enabled());
    }

    #[test]
    fn egress_jobs_disabled_in_airgap() {
        // Air-gap mode: egress jobs must be skipped at their spawn sites.
        let config = ApiConfig {
            airgap: true,
            ..ApiConfig::default()
        };
        assert!(!config.egress_jobs_enabled());
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 3000,
            database_url: "postgres://localhost/nanosiem".to_string(),
            cors_origins: vec!["*".to_string()],
            auth_enabled: false,
            api_key: None,
            deployment_mode: DeploymentMode::SelfHosted,
            demo_session_ttl_hours: 72,
            demo_max_sessions_per_ip: 10,
            license_url: None,
            license_token: None,
            deployment_id: None,
            airgap: false,
        }
    }
}
