// SPDX-License-Identifier: AGPL-3.0-or-later

//! API configuration

use std::env;

/// Deployment mode for this API process.
///
/// `EnterpriseShared` is intentionally distinct from `Managed`: existing
/// managed deployments are dedicated/customer-owned enterprise installations,
/// while shared multi-tenancy must be enabled explicitly and audited one call
/// site at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentMode {
    /// Dedicated/customer-owned enterprise: AI pre-configured, settings locked.
    Managed,
    /// Nano-operated shared enterprise control and data plane.
    #[cfg(feature = "enterprise")]
    EnterpriseShared,
    /// Self-hosted / BYOC: user manages everything
    SelfHosted,
    /// Demo: shared instance with session-scoped ephemeral users
    Demo,
}

impl DeploymentMode {
    #[cfg(feature = "enterprise")]
    pub fn soar_smtp_deployment(self) -> nanosiem_enterprise::soar::notify::smtp::SmtpDeployment {
        use nanosiem_enterprise::soar::notify::smtp::SmtpDeployment;
        match self {
            Self::SelfHosted => SmtpDeployment::SelfHosted,
            Self::Managed | Self::EnterpriseShared => SmtpDeployment::Hosted,
            Self::Demo => SmtpDeployment::Demo,
        }
    }

    pub fn is_managed(&self) -> bool {
        matches!(self, DeploymentMode::Managed)
    }

    #[cfg(feature = "enterprise")]
    pub fn is_enterprise_shared(&self) -> bool {
        matches!(self, DeploymentMode::EnterpriseShared)
    }

    pub fn is_demo(&self) -> bool {
        matches!(self, DeploymentMode::Demo)
    }

    /// Parse the explicit deployment profile without silently changing an
    /// unknown non-empty value into self-hosted mode.
    ///
    /// Empty/unset remains the open-core default. `selfhosted` is retained for
    /// compatibility with `scripts/start-microservices-dev.sh`, while
    /// `self-hosted` matches the existing system API spelling.
    fn from_env_value(value: Option<&str>) -> Result<Self, String> {
        match value {
            None | Some("") | Some("selfhosted") | Some("self-hosted") => Ok(Self::SelfHosted),
            Some("managed") => Ok(Self::Managed),
            #[cfg(feature = "enterprise")]
            Some("enterprise_shared") => Ok(Self::EnterpriseShared),
            #[cfg(not(feature = "enterprise"))]
            Some("enterprise_shared") => Err(
                "DEPLOYMENT_MODE=enterprise_shared is the hosted profile and needs the enterprise build"
                    .to_string(),
            ),
            Some("demo") => Ok(Self::Demo),
            Some(value) => Err(format!(
                "invalid DEPLOYMENT_MODE {value:?}; expected managed, enterprise_shared, selfhosted, self-hosted, demo, or an empty/unset value"
            )),
        }
    }

    /// Stable value exposed by `/api/system/config`.
    ///
    /// Demo historically reported as `self-hosted`; preserve that external
    /// behavior during this boundary-only phase. Shared enterprise must be
    /// distinguishable so later tenant work can opt in explicitly.
    pub fn system_api_value(&self) -> &'static str {
        match self {
            Self::Managed => "managed",
            #[cfg(feature = "enterprise")]
            Self::EnterpriseShared => "enterprise_shared",
            Self::SelfHosted | Self::Demo => "self-hosted",
        }
    }
}

/// How logs reach this install (NAN-3844).
///
/// `install.sh --tenzir` (NAN-3807) records `NANO_VECTOR_PROFILE=none` and
/// starts open core with no Vector and no connector runner: data arrives only
/// through the Tenzir RustFS bucket drop. Every surface that renders into, or
/// delivers through, Vector (HTTP/HEC/OTLP push, pull connectors, directory
/// sync, parser deploys, synthetic checks) cannot work there, so the API
/// reports the mode on `/api/capabilities` and refuses those mutations with a
/// clear error instead of letting them fail downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IngestMode {
    /// Vector is installed (default, and every unknown value — the installer
    /// falls back to Vector the same way).
    #[default]
    Vector,
    /// Tenzir-direct: bucket drop only, no Vector.
    TenzirOnly,
}

impl IngestMode {
    /// Resolve from `NANO_VECTOR_PROFILE`. Only the exact installer value
    /// `none` selects Tenzir-only, matching `resolve_vector_profile` in
    /// install.sh, which treats anything else as the default Vector profile.
    pub fn from_vector_profile(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some("none") => Self::TenzirOnly,
            _ => Self::Vector,
        }
    }

    pub fn is_tenzir_only(&self) -> bool {
        matches!(self, Self::TenzirOnly)
    }

    /// Stable wire value for `/api/capabilities` (`ingestMode`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Vector => "vector",
            Self::TenzirOnly => "tenzir_only",
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
    /// Unique deployment identifier assigned by the platform
    pub deployment_id: Option<String>,
    /// Air-gapped install: no outbound internet. Orthogonal to `deployment_mode`
    /// (an air-gap install is still self-hosted), so it's a separate flag rather
    /// than a 4th `DeploymentMode` variant. Read from `AIRGAP_MODE` ("1"/"true").
    /// When true, marketplace egress paths (deno/native/identity sync, GitHub
    /// repo sync) refuse cleanly instead of attempting a doomed fetch — bundles
    /// come in via the air-gap import surface instead.
    pub airgap: bool,
    /// Active schema profile selected for this deployment (scoping §2.4).
    /// Resolved from `NANO_SCHEMA_PROFILE` at boot (unset | `ocsf`; NAN-3491).
    /// Boot fails fast on any other value, including the removed `udm`.
    /// The resolved `Arc<dyn SchemaProfile>` is threaded into the search path
    /// from `AppState`; this field records the choice for reporting.
    pub schema_id: nanosiem_core::schema::SchemaId,
    /// Whether this process serves the canonical OCSF 1.9 object-lake lane.
    ///
    /// `schema_id` alone cannot express the distinction between the legacy
    /// ClickHouse OCSF compatibility layout and the strict Iceberg/lake layout.
    /// Capture the backend choice once at boot so API-owned search services,
    /// scheduled detections, field validation, and the search microservice all
    /// resolve the same physical schema.
    pub canonical_lake_ocsf: bool,
    /// Ingest mode from `NANO_VECTOR_PROFILE` (NAN-3844). Shared tenants
    /// always report `Vector`; only an open-core `install.sh --tenzir` sets it.
    pub ingest_mode: IngestMode,
    /// Sovereign installation (NAN-4666), derived from the installation facts
    /// at `/app/sovereign`, never from an environment flag. Implies `airgap`.
    pub sovereign: bool,
}

/// How this process enforces the license at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseBootMode {
    /// Hosted/BYOC phone-home status poller (LICENSE_URL + token + id).
    Poll,
    /// Offline: locked until a valid, non-expired offline license is imported.
    LockedUnlessValid,
    /// Open-core / unconfigured: unrestricted.
    Unrestricted,
}

impl ApiConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        // NAN-3491: one central resolution of backend + schema. Unset selects
        // canonical OCSF on the lake; a legacy value (`clickhouse`, `shadow`,
        // `udm`) is a hard boot failure, never a silent conversion.
        let runtime =
            nanosiem_core::schema::runtime_profile_from_env().unwrap_or_else(|e| panic!("{e}"));
        let schema_id = runtime.schema;
        let canonical_lake_ocsf = Self::is_canonical_lake_ocsf(runtime);

        let cors_origins = env::var("CORS_ORIGINS")
            .unwrap_or_else(|_| "*".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        let mut config = Self {
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
            deployment_mode: DeploymentMode::from_env_value(
                env::var("DEPLOYMENT_MODE").ok().as_deref(),
            )
            .unwrap_or_else(|error| panic!("{error}")),
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
            canonical_lake_ocsf,
            ingest_mode: IngestMode::from_vector_profile(
                env::var("NANO_VECTOR_PROFILE").ok().as_deref(),
            ),
            sovereign: false,
        };
        // NAN-4666: sovereign facts are the only source for a sovereign
        // runtime. Missing or invalid facts refuse to boot (no localhost).
        match nanosiem_core::sovereign_runtime::process_runtime() {
            Ok(Some(sovereign)) => config.apply_sovereign(sovereign),
            Ok(None) => {}
            Err(error) => panic!("Refusing to start: {error}"),
        }
        // The hosted-shared substrate has no per-install Vector profile; a
        // stray NANO_VECTOR_PROFILE there must not switch tenant surfaces off.
        #[cfg(feature = "enterprise")]
        if config.deployment_mode.is_enterprise_shared() {
            config.ingest_mode = IngestMode::Vector;
        }
        config
            .validate_runtime_security()
            .unwrap_or_else(|error| panic!("{error}"));
        config
    }

    /// Apply the fixed sovereign policy from validated installation facts:
    /// an offline (airgap-equivalent) runtime, the product database and the
    /// browser origin from the facts, self-hosted settings, no phone-home.
    /// `detect_at` already refused env that would contradict the facts.
    pub fn apply_sovereign(&mut self, sovereign: &nanosiem_core::sovereign_runtime::SovereignRuntime) {
        self.sovereign = true;
        self.airgap = !sovereign.egress_jobs_enabled();
        self.deployment_mode = DeploymentMode::SelfHosted;
        self.database_url = sovereign.database_url().to_string();
        self.cors_origins = vec![sovereign.browser_origin()];
        self.license_url = None;
        self.license_token = None;
    }

    /// License enforcement chosen at boot. A sovereign runtime is always
    /// locked unless a valid offline license is installed.
    pub fn license_boot_mode(&self) -> LicenseBootMode {
        if self.sovereign || (self.airgap && !self.is_license_enabled()) {
            LicenseBootMode::LockedUnlessValid
        } else if self.is_license_enabled() {
            LicenseBootMode::Poll
        } else {
            LicenseBootMode::Unrestricted
        }
    }

    /// Whether a resolved runtime profile is the canonical OCSF 1.9 lake lane.
    /// Since NAN-3491 every profile `runtime_profile_from_env` accepts is.
    fn is_canonical_lake_ocsf(runtime: nanosiem_core::schema::RuntimeProfile) -> bool {
        runtime.schema == nanosiem_core::schema::SchemaId::Ocsf
            && runtime.backend == nanosiem_core::schema::LogQueryBackend::Lake
    }

    /// Refuse deployment settings that would weaken the shared browser
    /// boundary. Dedicated/open-core development keeps its existing localhost
    /// behavior; the hosted profile has no insecure-cookie or wildcard-CORS
    /// escape hatch.
    fn validate_runtime_security(&self) -> Result<(), String> {
        let dev_mode =
            env::var("NANOSIEM_DEV_MODE").is_ok_and(|value| value.eq_ignore_ascii_case("true"));
        self.validate_runtime_security_values(dev_mode)
    }

    fn validate_runtime_security_values(&self, dev_mode: bool) -> Result<(), String> {
        // Open builds have no shared profile, so there is nothing to refuse.
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = dev_mode;
            Ok(())
        }
        #[cfg(feature = "enterprise")]
        {
            if !self.deployment_mode.is_enterprise_shared() {
                return Ok(());
            }
            if dev_mode {
                return Err(
                    "CRITICAL SECURITY ERROR: NANOSIEM_DEV_MODE cannot be enabled in enterprise_shared; shared session cookies must always be Secure"
                        .to_string(),
                );
            }
            if self.cors_origins.is_empty()
                || self
                    .cors_origins
                    .iter()
                    .any(|origin| origin.is_empty() || origin == "*")
            {
                return Err(
                    "CRITICAL SECURITY ERROR: enterprise_shared requires an explicit HTTPS CORS_ORIGINS allowlist"
                        .to_string(),
                );
            }
            for origin in &self.cors_origins {
                let parsed = url::Url::parse(origin).map_err(|_| {
                    format!(
                        "CRITICAL SECURITY ERROR: enterprise_shared CORS origin {origin:?} is invalid"
                    )
                })?;
                if parsed.scheme() != "https"
                    || parsed.host_str().is_none()
                    || parsed.host_str().is_some_and(|host| host.contains('*'))
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || parsed.path() != "/"
                    || parsed.query().is_some()
                    || parsed.fragment().is_some()
                {
                    return Err(format!(
                        "CRITICAL SECURITY ERROR: enterprise_shared CORS origin {origin:?} must be an exact HTTPS origin without credentials, path, query, or fragment"
                    ));
                }
            }
            Ok(())
        }
    }

    /// Resolve the active schema profile for this deployment. Built from
    /// [`schema_id`](ApiConfig::schema_id) (already validated at
    /// [`from_env`](ApiConfig::from_env)) so AppState can inject it into the
    /// search path without re-reading the environment.
    ///
    /// **Boot only.** Under the canonical lake backend this reads the lake
    /// worker config and parses the signed source manifest it points at (tens
    /// of MB of JSON), so it must be called exactly once and the resulting
    /// `Arc` shared — request handlers go through
    /// `AppState::schema_profile()`. It returns `Result` rather than panicking
    /// so the single boot caller can refuse to serve: an unresolvable or
    /// untrusted manifest is fail-closed by design (NAN-2361), never a
    /// silently empty field inventory.
    pub fn try_schema_profile(
        &self,
    ) -> Result<std::sync::Arc<dyn nanosiem_core::schema::SchemaProfile>, String> {
        if self.canonical_lake_ocsf {
            nanosiem_core::schema::lake_ocsf_profile_from_snapshot_env()
                .map_err(|error| format!("invalid lake schema manifest: {error}"))
        } else {
            Ok(nanosiem_core::schema::profile_for_id(self.schema_id))
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
    use nanosiem_core::schema::SchemaProfile;

    #[cfg(feature = "enterprise")]
    #[test]
    fn smtp_private_networks_require_the_typed_self_hosted_profile() {
        use nanosiem_enterprise::soar::notify::smtp::SmtpDeployment;
        assert_eq!(DeploymentMode::SelfHosted.soar_smtp_deployment(), SmtpDeployment::SelfHosted);
        assert_eq!(DeploymentMode::Demo.soar_smtp_deployment(), SmtpDeployment::Demo);
        for mode in [DeploymentMode::Managed, DeploymentMode::EnterpriseShared] {
            assert_eq!(mode.soar_smtp_deployment(), SmtpDeployment::Hosted);
        }
    }
    #[cfg(feature = "enterprise")]
    #[test]
    fn deployment_mode_requires_explicit_enterprise_shared_profile() {
        assert_eq!(
            DeploymentMode::from_env_value(Some("enterprise_shared")),
            Ok(DeploymentMode::EnterpriseShared)
        );
        assert!(DeploymentMode::EnterpriseShared.is_enterprise_shared());
        assert!(!DeploymentMode::EnterpriseShared.is_managed());
        assert!(!DeploymentMode::Managed.is_enterprise_shared());
    }

    #[test]
    fn deployment_mode_preserves_existing_profiles() {
        for value in [None, Some(""), Some("selfhosted"), Some("self-hosted")] {
            assert_eq!(
                DeploymentMode::from_env_value(value),
                Ok(DeploymentMode::SelfHosted)
            );
        }
        assert_eq!(
            DeploymentMode::from_env_value(Some("managed")),
            Ok(DeploymentMode::Managed)
        );
        assert_eq!(
            DeploymentMode::from_env_value(Some("demo")),
            Ok(DeploymentMode::Demo)
        );
    }

    #[test]
    fn deployment_mode_rejects_unknown_non_empty_values() {
        let error = DeploymentMode::from_env_value(Some("enterprise-shared"))
            .expect_err("an inexact shared profile must fail closed");
        assert!(error.contains("invalid DEPLOYMENT_MODE"), "{error}");

        assert!(DeploymentMode::from_env_value(Some("Managed")).is_err());
        assert!(DeploymentMode::from_env_value(Some(" ")).is_err());
    }

    #[test]
    fn deployment_mode_system_api_values_are_stable() {
        assert_eq!(DeploymentMode::Managed.system_api_value(), "managed");
        #[cfg(feature = "enterprise")]
        assert_eq!(
            DeploymentMode::EnterpriseShared.system_api_value(),
            "enterprise_shared"
        );
        assert_eq!(DeploymentMode::SelfHosted.system_api_value(), "self-hosted");
        assert_eq!(DeploymentMode::Demo.system_api_value(), "self-hosted");
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn enterprise_shared_requires_secure_cookies_and_exact_https_cors_origins() {
        let shared = ApiConfig {
            deployment_mode: DeploymentMode::EnterpriseShared,
            cors_origins: vec!["https://tenant.nano.rs".to_string()],
            ..ApiConfig::default()
        };
        assert!(shared.validate_runtime_security_values(false).is_ok());
        assert!(shared.validate_runtime_security_values(true).is_err());

        for origins in [
            vec![],
            vec!["*".to_string()],
            vec!["".to_string()],
            vec!["http://tenant.nano.rs".to_string()],
            vec!["https://tenant.nano.rs/path".to_string()],
            vec!["https://user@tenant.nano.rs".to_string()],
            vec!["https://*.nano.rs".to_string()],
        ] {
            let config = ApiConfig {
                deployment_mode: DeploymentMode::EnterpriseShared,
                cors_origins: origins,
                ..ApiConfig::default()
            };
            assert!(config.validate_runtime_security_values(false).is_err());
        }
    }

    #[test]
    fn dedicated_profiles_preserve_the_existing_development_cookie_and_cors_policy() {
        for deployment_mode in [
            DeploymentMode::Managed,
            DeploymentMode::SelfHosted,
            DeploymentMode::Demo,
        ] {
            let config = ApiConfig {
                deployment_mode,
                cors_origins: vec!["*".to_string()],
                ..ApiConfig::default()
            };
            assert!(config.validate_runtime_security_values(true).is_ok());
        }
    }

    /// NAN-4666 fixture: the installer-persisted sovereign facts directory.
    fn sovereign_facts(dir: &std::path::Path) -> nanosiem_core::sovereign_runtime::SovereignRuntime {
        use base64::Engine as _;
        use std::os::unix::fs::PermissionsExt;
        use nanosiem_core::sovereign_runtime::*;
        let root = dir.join("sovereign");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let document = serde_json::json!({
            "schema_version": 1,
            "inputs": {"domain": "siem.customer.example", "idp": {"kind": "oidc", "issuer": "https://idp.customer.example"}, "connectivity": "connected"},
            "derived": {"installation_id": "inst-1", "organization_id": "org-1", "revision": 1, "release_epoch": 1},
            "target": {"kind": "linux", "inputs": {}, "derived": {}}
        });
        let deployment = serde_json::json!({
            "installationDocument": base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&document).unwrap()),
            "postgres": {"runtimeUrl": {"id": "postgres-runtime"}, "migratorUrl": {"id": "postgres-migrator"}, "ca": {"id": "postgres-ca"}},
            "coordination": {"url": {"id": "coordination-url"}, "ca": {"id": "coordination-ca"}},
            "identity": {"sessionSecret": {"id": "session-secret"}, "oidcClient": {"id": "oidc-client"}, "recoveryAuthority": {"id": "bootstrap-verifier"}},
            "releaseDigest": format!("sha256:{}", "b".repeat(64)),
            "listen": {"host": "127.0.0.1", "port": 13000}
        });
        for (name, bytes) in [
            (DEPLOYMENT_FILE, serde_json::to_vec(&deployment).unwrap()),
            (PRODUCT_POSTGRES_RUNTIME_FILE, b"postgresql://nano_runtime:pw@pg.customer.internal/nano?sslmode=verify-full".to_vec()),
            (PRODUCT_POSTGRES_CA_FILE, b"synthetic ca".to_vec()),
        ] {
            let path = root.join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        SovereignRuntime::load(&root).unwrap()
    }

    /// NAN-4666: sovereign facts give an offline runtime with no egress
    /// schedulers, the product DB from facts, the customer browser origin,
    /// no phone-home, and the license locked unless a valid offline license
    /// is installed.
    #[test]
    fn sovereign_facts_select_offline_runtime_and_locked_license() {
        let dir = tempfile::tempdir().unwrap();
        let sovereign = sovereign_facts(dir.path());
        // Even a config that had hosted values ends in the sovereign policy.
        let mut config = ApiConfig {
            license_url: Some("https://api.nano.rs/api/license/status".into()),
            license_token: Some("t".into()),
            deployment_id: Some("d".into()),
            ..ApiConfig::default()
        };
        config.apply_sovereign(&sovereign);
        assert!(config.sovereign);
        assert!(config.airgap);
        assert!(!config.egress_jobs_enabled(), "no internet egress schedulers");
        assert_eq!(config.deployment_mode, DeploymentMode::SelfHosted);
        assert!(!config.is_license_enabled(), "no phone-home");
        assert!(config.license_url.is_none() && config.license_token.is_none());
        // Sovereign wins over any phone-home config, even with airgap off.
        let forced = ApiConfig {
            sovereign: true,
            airgap: false,
            license_url: Some("u".into()),
            license_token: Some("t".into()),
            deployment_id: Some("d".into()),
            ..ApiConfig::default()
        };
        assert_eq!(forced.license_boot_mode(), LicenseBootMode::LockedUnlessValid);
        assert_eq!(config.license_boot_mode(), LicenseBootMode::LockedUnlessValid);
        assert_eq!(config.cors_origins, vec!["https://siem.customer.example".to_string()]);
        assert!(config.database_url.starts_with("postgresql://nano_runtime:pw@pg.customer.internal/nano?sslmode=verify-full&sslrootcert="));
        assert!(!config.database_url.contains("localhost"));
    }

    /// NAN-4666: hosted / open-core behavior is unchanged. No sovereign mount
    /// on a normal host, and the env-driven license decisions keep their
    /// previous precedence.
    #[test]
    fn hosted_license_and_egress_behavior_is_unchanged() {
        assert!(nanosiem_core::sovereign_runtime::process_runtime().unwrap().is_none());
        let default = ApiConfig::default();
        assert!(!default.sovereign);
        assert_eq!(default.database_url, "postgres://localhost/nanosiem");
        assert_eq!(default.license_boot_mode(), LicenseBootMode::Unrestricted);
        assert!(default.egress_jobs_enabled());
        let licensed = ApiConfig {
            license_url: Some("u".into()),
            license_token: Some("t".into()),
            deployment_id: Some("d".into()),
            ..ApiConfig::default()
        };
        assert_eq!(licensed.license_boot_mode(), LicenseBootMode::Poll);
        // Pre-NAN-4666 precedence: a configured LICENSE_URL wins over AIRGAP_MODE.
        let licensed_airgap = ApiConfig { airgap: true, ..licensed.clone() };
        assert_eq!(licensed_airgap.license_boot_mode(), LicenseBootMode::Poll);
        let airgap = ApiConfig { airgap: true, ..ApiConfig::default() };
        assert_eq!(airgap.license_boot_mode(), LicenseBootMode::LockedUnlessValid);
        assert!(!airgap.sovereign);
    }

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
    fn canonical_lake_ocsf_profile_is_strict_1_9() {
        let profile = nanosiem_core::schema::OcsfProfile::try_lake_1_9_with_snapshot_field_types(
            std::collections::BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(profile.timestamp_expr(), "time");
        assert!(profile.is_known_field("src_endpoint.ip"));
        // NAN-2447 (d4b291b09): product UDM names are query aliases on the
        // lake profile, so they are "known" — but they must resolve to the
        // strict OCSF 1.9 column, never to a compatibility column.
        use nanosiem_core::schema::FieldResolution;
        assert_eq!(
            profile.resolve("src_ip"),
            FieldResolution::ExplicitColumn("src_endpoint.ip".into())
        );
        assert_eq!(
            profile.resolve("timestamp"),
            FieldResolution::ExplicitColumn("time".into())
        );
        assert!(!profile.is_known_field("not_an_ocsf_field"));
    }

    /// NAN-3491: unset and the hosted `ocsf`+`lake` pair both select the
    /// canonical lake lane (hosted takes exactly the branch it took before);
    /// every legacy value is refused at boot.
    #[test]
    fn runtime_profile_resolution_selects_the_canonical_lake_lane() {
        use nanosiem_core::schema::runtime_profile::resolve_runtime_profile;
        for (schema, backend) in [
            (None, None),
            (Some(""), Some("")),
            (Some("ocsf"), Some("lake")),
        ] {
            let runtime = resolve_runtime_profile(schema, backend).unwrap();
            assert!(ApiConfig::is_canonical_lake_ocsf(runtime));
            assert_eq!(runtime.schema, nanosiem_core::schema::SchemaId::Ocsf);
        }
        for (schema, backend) in [
            (Some("udm"), None),
            (None, Some("clickhouse")),
            (Some("ocsf"), Some("shadow")),
            (Some("udm"), Some("clickhouse")),
        ] {
            assert!(resolve_runtime_profile(schema, backend).is_err());
        }
    }

    #[test]
    fn clickhouse_ocsf_config_preserves_the_compatibility_profile() {
        let config = ApiConfig {
            schema_id: nanosiem_core::schema::SchemaId::Ocsf,
            canonical_lake_ocsf: false,
            ..ApiConfig::default()
        };

        let profile = config.try_schema_profile().unwrap();
        assert_eq!(profile.timestamp_expr(), "timestamp");
        assert_eq!(profile.table_name(), "nanosiem.ocsf_logs");
    }

    /// NAN-2361: boot must refuse to serve when the lake manifest cannot be
    /// resolved. Previously this panicked from inside request handlers; the
    /// error now travels to the boot caller, but it must still be an error and
    /// never a profile with an empty field inventory.
    #[test]
    fn canonical_lake_boot_fails_closed_on_unreadable_manifest() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let manifest = std::env::var(nanosiem_core::schema::LAKE_SCHEMA_MANIFEST_ENV).ok();
        let worker = std::env::var(nanosiem_core::schema::LAKE_WORKER_CONFIG_ENV).ok();
        std::env::set_var(
            nanosiem_core::schema::LAKE_SCHEMA_MANIFEST_ENV,
            "/nonexistent/nan2361/source_manifest.json",
        );
        std::env::remove_var(nanosiem_core::schema::LAKE_WORKER_CONFIG_ENV);

        let config = ApiConfig {
            schema_id: nanosiem_core::schema::SchemaId::Ocsf,
            canonical_lake_ocsf: true,
            ..ApiConfig::default()
        };
        let error = match config.try_schema_profile() {
            Err(error) => error,
            Ok(_) => panic!("unreadable manifest must not yield a usable profile"),
        };
        assert!(error.contains("invalid lake schema manifest"), "{error}");

        match manifest {
            Some(value) => {
                std::env::set_var(nanosiem_core::schema::LAKE_SCHEMA_MANIFEST_ENV, value)
            }
            None => std::env::remove_var(nanosiem_core::schema::LAKE_SCHEMA_MANIFEST_ENV),
        }
        if let Some(value) = worker {
            std::env::set_var(nanosiem_core::schema::LAKE_WORKER_CONFIG_ENV, value);
        }
    }

    #[test]
    fn ingest_mode_is_tenzir_only_only_for_the_installer_none_value() {
        assert_eq!(IngestMode::from_vector_profile(Some("none")), IngestMode::TenzirOnly);
        assert_eq!(IngestMode::from_vector_profile(Some(" none\n")), IngestMode::TenzirOnly);
        for value in [None, Some(""), Some("lean"), Some("NONE"), Some("bogus")] {
            assert_eq!(IngestMode::from_vector_profile(value), IngestMode::Vector, "{value:?}");
        }
        assert_eq!(IngestMode::TenzirOnly.as_str(), "tenzir_only");
        assert_eq!(IngestMode::Vector.as_str(), "vector");
        assert_eq!(ApiConfig::default().ingest_mode, IngestMode::Vector);
    }

    /// Manifest env vars are process-global; serialize the tests that mutate
    /// them so a parallel run cannot observe another test's window.
    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        &LOCK
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
            canonical_lake_ocsf: false,
            ingest_mode: IngestMode::Vector,
            sovereign: false,
        }
    }
}
