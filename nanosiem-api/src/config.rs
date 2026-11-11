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

/// Complete online license tuple. Partial tuples are configuration errors and
/// must never disable enforcement.
#[derive(Debug, Clone)]
pub struct OnlineLicenseConfig {
    pub url: String,
    pub token: String,
    pub deployment_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("incomplete online license configuration; missing {missing}")]
pub struct LicenseConfigError {
    missing: String,
}

impl DeploymentMode {
    pub fn is_managed(&self) -> bool {
        matches!(self, DeploymentMode::Managed)
    }

    pub fn is_demo(&self) -> bool {
        matches!(self, DeploymentMode::Demo)
    }

    /// V2 operator identity used for AI allowance semantics. Both the managed
    /// product and the shared demo are platform-operated; only BYOC installs
    /// are self-run.
    pub fn entitlement_operator(&self) -> nanosiem_core::EntitlementOperator {
        match self {
            Self::Managed | Self::Demo => nanosiem_core::EntitlementOperator::Hosted,
            Self::SelfHosted => nanosiem_core::EntitlementOperator::SelfRun,
        }
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
    /// Active schema profile selected for this deployment (scoping §2.4).
    /// Resolved from `NANO_SCHEMA_PROFILE` at boot (`udm` default | `ocsf`).
    /// Boot fails fast on an unrecognized value (DualPool philosophy, NAN-800).
    /// The resolved `Arc<dyn SchemaProfile>` is threaded into the search path
    /// from `AppState`; this field records the choice for reporting.
    pub schema_id: nanosiem_core::schema::SchemaId,
}

impl ApiConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        // Resolve the active schema profile early; an unrecognized
        // NANO_SCHEMA_PROFILE is a hard boot failure (fail-fast, NAN-800) rather
        // than a silent UDM fallback against a possibly-OCSF table.
        let schema_raw = env::var(nanosiem_core::schema::SCHEMA_PROFILE_ENV).unwrap_or_default();
        let schema_id = nanosiem_core::schema::SchemaId::from_env_str(&schema_raw)
            .unwrap_or_else(|e| panic!("{e}"));

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
            schema_id,
        }
    }

    /// Resolve the active schema profile for this deployment. Built from
    /// [`schema_id`](ApiConfig::schema_id) (already validated at
    /// [`from_env`](ApiConfig::from_env)) so AppState can inject it into the
    /// search path without re-reading the environment.
    pub fn schema_profile(&self) -> std::sync::Arc<dyn nanosiem_core::schema::SchemaProfile> {
        nanosiem_core::schema::profile_for_id(self.schema_id)
    }

    /// Get the bind address
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Resolve the explicit online admission mode. `None` selects the signed
    /// C05/legacy authority. A partial tuple is an error, never a bypass.
    ///
    /// Online intent is expressed by the license credentials
    /// (`LICENSE_URL`/`LICENSE_TOKEN`). `NANO_DEPLOYMENT_ID` alone is not
    /// online intent: it is also the installation identity written by the
    /// installer/inventory renderer and the tenant-health exporter identity,
    /// so every multi-node Compose jobs container and every health-exporting
    /// Helm jobs pod carries it without any online license. Treating it as a
    /// partial online tuple would lock those installs even with a valid C05.
    /// Selecting C05 here is still fail-closed: C05 admits nothing without a
    /// verified signed license or the bounded legacy upgrade grace.
    pub fn online_license_config(&self) -> Result<Option<OnlineLicenseConfig>, LicenseConfigError> {
        if self.airgap {
            return Ok(None);
        }

        let populated = |value: &Option<String>| {
            value
                .as_deref()
                .is_some_and(|candidate| !candidate.trim().is_empty())
        };
        let present = [
            populated(&self.license_url),
            populated(&self.license_token),
            populated(&self.deployment_id),
        ];
        if !present[0] && !present[1] {
            return Ok(None);
        }
        if present.iter().all(|value| *value) {
            return Ok(Some(OnlineLicenseConfig {
                url: self
                    .license_url
                    .as_deref()
                    .expect("presence checked")
                    .trim()
                    .to_owned(),
                token: self
                    .license_token
                    .as_deref()
                    .expect("presence checked")
                    .trim()
                    .to_owned(),
                deployment_id: self
                    .deployment_id
                    .as_deref()
                    .expect("presence checked")
                    .trim()
                    .to_owned(),
            }));
        }

        let missing = [
            ("LICENSE_URL", !present[0]),
            ("LICENSE_TOKEN", !present[1]),
            ("NANO_DEPLOYMENT_ID", !present[2]),
        ]
        .into_iter()
        .filter_map(|(name, missing)| missing.then_some(name))
        .collect::<Vec<_>>()
        .join(", ");
        Err(LicenseConfigError { missing })
    }

    /// Returns true only for a complete online license tuple.
    pub fn is_license_enabled(&self) -> bool {
        matches!(self.online_license_config(), Ok(Some(_)))
    }

    /// Whether the offline C05 authority admits this install, and therefore
    /// whether its license admin endpoints (import/renew/clock recovery) may
    /// accept C05 files. Boot selects the same authority on the same
    /// condition; it is not tied to AIRGAP_MODE (NAN-5086). A partial online
    /// tuple fails closed and accepts no C05 file.
    pub fn uses_c05_authority(&self) -> bool {
        matches!(self.online_license_config(), Ok(None))
    }

    /// Whether background jobs that make outbound network calls (platform
    /// feed bundle check, identity sync, GitHub repo auto-sync, marketplace, model
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

    #[test]
    fn v2_operator_distinguishes_platform_and_customer_operation() {
        assert_eq!(
            DeploymentMode::Managed.entitlement_operator(),
            nanosiem_core::EntitlementOperator::Hosted
        );
        assert_eq!(
            DeploymentMode::Demo.entitlement_operator(),
            nanosiem_core::EntitlementOperator::Hosted
        );
        assert_eq!(
            DeploymentMode::SelfHosted.entitlement_operator(),
            nanosiem_core::EntitlementOperator::SelfRun
        );
    }

    #[test]
    fn online_licence_requires_the_complete_tuple() {
        let complete = ApiConfig {
            license_url: Some("https://license.example.test".into()),
            license_token: Some("token".into()),
            deployment_id: Some("deployment".into()),
            ..ApiConfig::default()
        };
        assert!(complete.online_license_config().unwrap().is_some());

        for partial in [
            ApiConfig {
                license_url: Some("https://license.example.test".into()),
                license_token: Some("token".into()),
                ..ApiConfig::default()
            },
            ApiConfig {
                license_url: Some("https://license.example.test".into()),
                deployment_id: Some("deployment".into()),
                ..ApiConfig::default()
            },
            ApiConfig {
                license_token: Some("token".into()),
                deployment_id: Some("deployment".into()),
                ..ApiConfig::default()
            },
        ] {
            assert!(partial.online_license_config().is_err());
            assert!(!partial.is_license_enabled());
        }

        let blank_token = ApiConfig {
            license_url: Some("https://license.example.test".into()),
            license_token: Some("   ".into()),
            deployment_id: Some("deployment".into()),
            ..ApiConfig::default()
        };
        assert!(blank_token.online_license_config().is_err());
    }

    /// Regression: the v2 multi-node Compose inventory and the Helm health
    /// exporter give jobs `NANO_DEPLOYMENT_ID` with no license credentials.
    /// That is an installation identity, not a partial online tuple, so it must
    /// select the fail-closed C05 authority rather than a permanent lock.
    #[test]
    fn deployment_identity_alone_selects_c05_authority() {
        let identity_only = ApiConfig {
            deployment_id: Some("nano-prod-a1".into()),
            ..ApiConfig::default()
        };
        assert!(identity_only.online_license_config().unwrap().is_none());
        assert!(!identity_only.is_license_enabled());

        let blank_credentials = ApiConfig {
            license_url: Some(" ".into()),
            license_token: Some("".into()),
            deployment_id: Some("nano-prod-a1".into()),
            ..ApiConfig::default()
        };
        assert!(blank_credentials.online_license_config().unwrap().is_none());
    }

    /// Legacy managed Compose tenants (v0.1.x platform renderer) carry
    /// `LICENSE_URL`, `DEPLOYMENT_TOKEN` (forwarded as `LICENSE_TOKEN`) and
    /// `NANO_DEPLOYMENT_ID`; after the v2 layout transition the same three
    /// values must still select online admission.
    #[test]
    fn legacy_managed_tuple_selects_online_admission() {
        let managed = ApiConfig {
            license_url: Some("https://api.nano.rs/api/license/status".into()),
            license_token: Some("deployment-token".into()),
            deployment_id: Some("dep_01legacymanagedtenant".into()),
            ..ApiConfig::default()
        };
        let online = managed.online_license_config().unwrap().unwrap();
        assert_eq!(online.deployment_id, "dep_01legacymanagedtenant");
        assert!(managed.is_license_enabled());
    }

    #[test]
    fn no_online_tuple_or_airgap_selects_c05_authority() {
        assert!(ApiConfig::default()
            .online_license_config()
            .unwrap()
            .is_none());
        let airgap = ApiConfig {
            airgap: true,
            license_url: Some("ignored".into()),
            ..ApiConfig::default()
        };
        assert!(airgap.online_license_config().unwrap().is_none());
    }

    /// NAN-5086: a self-run install without an online tuple and without
    /// AIRGAP_MODE is admitted only by C05, so it must accept C05 files.
    /// Online-licensed and partial-tuple installs must not.
    #[test]
    fn c05_admin_follows_the_admission_authority_not_airgap() {
        let self_run = ApiConfig::default();
        assert!(!self_run.airgap);
        assert!(self_run.uses_c05_authority());

        let identity_only = ApiConfig {
            deployment_id: Some("nano-prod-a1".into()),
            ..ApiConfig::default()
        };
        assert!(identity_only.uses_c05_authority());

        let airgap = ApiConfig {
            airgap: true,
            license_url: Some("ignored".into()),
            license_token: Some("ignored".into()),
            deployment_id: Some("ignored".into()),
            ..ApiConfig::default()
        };
        assert!(airgap.uses_c05_authority());

        let online = ApiConfig {
            license_url: Some("https://license.example.test".into()),
            license_token: Some("token".into()),
            deployment_id: Some("deployment".into()),
            ..ApiConfig::default()
        };
        assert!(!online.uses_c05_authority());

        let partial = ApiConfig {
            license_url: Some("https://license.example.test".into()),
            ..ApiConfig::default()
        };
        assert!(!partial.uses_c05_authority());
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
            schema_id: nanosiem_core::schema::SchemaId::Udm,
        }
    }
}
