// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deployment security posture read from the process environment (security
//! review 2026-11-08, group B).
//!
//! Two jobs:
//!
//! 1. Resolve which credential gates the internal Vector config delivery
//!    (`/api/internal/vector-config/*`). It used to be the forwarder install
//!    token (`VECTOR_AUTH_TOKEN`), so every forwarder holding that token could
//!    download rendered configs (NAN-5042). Delivery now has its own credential,
//!    `NANO_VECTOR_CONFIG_DELIVERY_TOKEN`. During v2.0.x the install token is
//!    still accepted beside it (warned per caller): a role-split app host is
//!    upgraded first, and ingest hosts whose copied `.env` predates the token
//!    keep pulling parser publishes and ingest-token changes (including
//!    revocations) until their `.env` is updated. v2.1 removes that fallback;
//!    `NANO_VECTOR_CONFIG_DELIVERY_STRICT=true` enforces it now (fresh
//!    installs set it). Single-host stacks have no delivery consumer and
//!    switch it off with `NANO_VECTOR_CONFIG_DELIVERY=off`.
//! 2. Produce the deterministic findings that boot logs and the SIEM health
//!    report surface for insecure-but-still-accepted configurations, so an
//!    operator sees them before the v2.1 enforcement.
//!
//! Nothing here returns or logs a secret value.

use crate::known_public_secrets::{is_known_public, SecretKind};

/// The dedicated config-delivery credential.
pub const DELIVERY_TOKEN_ENV: &str = "NANO_VECTOR_CONFIG_DELIVERY_TOKEN";
/// `off` disables config delivery entirely (single-host stacks deliver Vector
/// config and the ingest tokens file on a shared volume instead).
pub const DELIVERY_SWITCH_ENV: &str = "NANO_VECTOR_CONFIG_DELIVERY";
/// The forwarder install token.
pub const INSTALL_TOKEN_ENV: &str = "VECTOR_AUTH_TOKEN";
/// `true` refuses the install token on delivery even when a dedicated token
/// exists (the v2.1 behaviour, available now).
pub const DELIVERY_STRICT_ENV: &str = "NANO_VECTOR_CONFIG_DELIVERY_STRICT";

/// Which credential the internal Vector config delivery accepts.
#[derive(Clone, PartialEq, Eq)]
pub enum VectorConfigDeliveryCredential {
    /// Delivery is off: every delivery route answers 404.
    Disabled(DeliveryDisabledReason),
    /// The dedicated `NANO_VECTOR_CONFIG_DELIVERY_TOKEN` only.
    Dedicated(String),
    /// v2.0.x compatibility: the dedicated token, and the forwarder install
    /// token for consumers whose configuration predates it (warned per
    /// caller). Removed in v2.1.
    DedicatedOrInstallToken { dedicated: String, install: String },
    /// Deprecated v2.0.x fallback when no dedicated token exists: the forwarder
    /// install token. Accepted with a warning; removed in v2.1.
    LegacyInstallToken(String),
}

impl std::fmt::Debug for VectorConfigDeliveryCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled(reason) => f.debug_tuple("Disabled").field(reason).finish(),
            Self::Dedicated(_) => f.write_str("Dedicated(<redacted>)"),
            Self::DedicatedOrInstallToken { .. } => {
                f.write_str("DedicatedOrInstallToken(<redacted>)")
            }
            Self::LegacyInstallToken(_) => f.write_str("LegacyInstallToken(<redacted>)"),
        }
    }
}

/// Why delivery is disabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryDisabledReason {
    /// `NANO_VECTOR_CONFIG_DELIVERY=off`.
    SwitchedOff,
    /// Neither token is configured.
    NoCredential,
    /// The dedicated token is a publicly known value (it is new in v2.0.1, so
    /// there is nothing to stay compatible with: refused outright).
    PublicDedicatedToken,
    /// No dedicated token and the install token is a publicly known value
    /// (NAN-5148). The v2.0.x install-token fallback is for private install
    /// tokens only: a public one would let anyone download rendered configs.
    PublicInstallToken,
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

/// Resolve the delivery credential from the delivery settings.
pub fn resolve_vector_config_delivery(
    switch: Option<&str>,
    dedicated: Option<&str>,
    install: Option<&str>,
    strict: bool,
) -> VectorConfigDeliveryCredential {
    use VectorConfigDeliveryCredential as C;
    if nonempty(switch).is_some_and(|s| s.eq_ignore_ascii_case("off")) {
        return C::Disabled(DeliveryDisabledReason::SwitchedOff);
    }
    if let Some(token) = nonempty(dedicated) {
        if is_known_public(SecretKind::VectorConfigDeliveryToken, token) {
            return C::Disabled(DeliveryDisabledReason::PublicDedicatedToken);
        }
        // NAN-5148: the v2.0.x install-token fallback never extends to a
        // publicly known install token, in strict or compatibility mode.
        return match nonempty(install).filter(|i| !is_known_public(SecretKind::VectorInstallToken, i)) {
            Some(install) if !strict && install != token => C::DedicatedOrInstallToken {
                dedicated: token.to_string(),
                install: install.to_string(),
            },
            _ => C::Dedicated(token.to_string()),
        };
    }
    match nonempty(install) {
        Some(token) if is_known_public(SecretKind::VectorInstallToken, token) => {
            C::Disabled(DeliveryDisabledReason::PublicInstallToken)
        }
        Some(token) => C::LegacyInstallToken(token.to_string()),
        None => C::Disabled(DeliveryDisabledReason::NoCredential),
    }
}

/// [`resolve_vector_config_delivery`] over the process environment.
pub fn vector_config_delivery_from_env() -> VectorConfigDeliveryCredential {
    let var = |name: &str| std::env::var(name).ok();
    resolve_vector_config_delivery(
        var(DELIVERY_SWITCH_ENV).as_deref(),
        var(DELIVERY_TOKEN_ENV).as_deref(),
        var(INSTALL_TOKEN_ENV).as_deref(),
        env_flag(DELIVERY_STRICT_ENV),
    )
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v.trim().eq_ignore_ascii_case("true"))
}

/// One deterministic posture finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostureFinding {
    pub title: String,
    pub description: String,
    /// "critical" | "high" | "medium"
    pub priority: &'static str,
}

/// The environment inputs [`posture_findings`] reads, as plain values so the
/// logic is testable without touching the process environment.
#[derive(Clone, Debug, Default)]
pub struct PostureInputs {
    pub install_token: Option<String>,
    pub delivery_switch: Option<String>,
    pub delivery_token: Option<String>,
    pub delivery_strict: bool,
    pub allow_default_keys: bool,
    pub base_url: Option<String>,
    /// `(env var, value)` for every database password the process sees.
    pub db_passwords: Vec<(String, String)>,
}

impl PostureInputs {
    pub fn from_env() -> Self {
        let var = |name: &str| std::env::var(name).ok();
        Self {
            install_token: var(INSTALL_TOKEN_ENV),
            delivery_switch: var(DELIVERY_SWITCH_ENV),
            delivery_token: var(DELIVERY_TOKEN_ENV),
            delivery_strict: env_flag(DELIVERY_STRICT_ENV),
            allow_default_keys: var("NANOSIEM_ALLOW_DEFAULT_KEYS")
                .is_some_and(|v| v.eq_ignore_ascii_case("true")),
            base_url: var("BASE_URL"),
            db_passwords: db_passwords_from_env(),
        }
    }
}

/// Every database password visible to this process: the `*_PASSWORD` env vars
/// and the password inside `DATABASE_URL`.
fn db_passwords_from_env() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = crate::known_public_secrets::DB_PASSWORD_ENV_VARS
        .iter()
        .filter_map(|name| std::env::var(name).ok().map(|v| (name.to_string(), v)))
        .collect();
    if let Some(password) = std::env::var("DATABASE_URL")
        .ok()
        .and_then(|u| url::Url::parse(&u).ok())
        .and_then(|u| u.password().map(|p| urlencoding::decode(p).map(|d| d.into_owned()).unwrap_or_else(|_| p.to_string())))
    {
        out.push(("DATABASE_URL".to_string(), password));
    }
    out
}

/// Whether a base URL points only at this machine (a development setup).
fn is_loopback_url(url: &str) -> bool {
    let rest = url
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let authority = rest.split('/').next().unwrap_or("");
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1") || host.ends_with(".localhost")
}

/// Every insecure-but-accepted deployment setting, most severe first.
pub fn posture_findings(inputs: &PostureInputs) -> Vec<PostureFinding> {
    let mut findings = Vec::new();
    let install_public = inputs
        .install_token
        .as_deref()
        .is_some_and(|t| is_known_public(SecretKind::VectorInstallToken, t));

    if install_public {
        findings.push(PostureFinding {
            title: "The Vector install token is a public default value".into(),
            description: "VECTOR_AUTH_TOKEN is set to a value nano shipped as a default or example \
                 (for example `nanosiem-default-token`), so anyone can use it to send events. \
                 Issue a named ingest token for each sender (Ingestion > Ingest tokens), move \
                 the senders to them, then turn the install token off. From v2.1 a public \
                 install token is refused."
                .into(),
            priority: "critical",
        });
    }

    let mut public_db: Vec<&str> = inputs
        .db_passwords
        .iter()
        .filter(|(_, value)| is_known_public(SecretKind::DbPassword, value))
        .map(|(name, _)| name.as_str())
        .collect();
    public_db.sort_unstable();
    public_db.dedup();
    if !public_db.is_empty() {
        findings.push(PostureFinding {
            title: "Database passwords are publicly known defaults".into(),
            description: format!(
                "{} hold a password nano shipped as a default or example (for example \
                 `nanosiem`). PostgreSQL and ClickHouse are reachable only on the internal \
                 network in the supported stacks, but anything on that network can log in. \
                 Change them together with the database (docs: Docker deployment > Changing \
                 a database password); nano does not change them automatically because the \
                 databases keep the password their data was created with.",
                public_db.join(", ")
            ),
            priority: "high",
        });
    }

    match resolve_vector_config_delivery(
        inputs.delivery_switch.as_deref(),
        inputs.delivery_token.as_deref(),
        inputs.install_token.as_deref(),
        inputs.delivery_strict,
    ) {
        VectorConfigDeliveryCredential::DedicatedOrInstallToken { .. } => {
            findings.push(PostureFinding {
                title: "Vector config delivery still accepts the forwarder install token".into(),
                description: format!(
                    "For v2.0.x compatibility, /api/internal/vector-config/* accepts \
                     VECTOR_AUTH_TOKEN as well as {DELIVERY_TOKEN_ENV}, so a config consumer \
                     whose .env predates the new token keeps receiving parser publishes and \
                     ingest-token changes. nano-api logs each caller that still uses the \
                     install token, with its IP address: copy the updated shared .env to that \
                     host and re-run install.sh there. Then set \
                     {DELIVERY_STRICT_ENV}=true on nano-api to refuse the install token now; \
                     v2.1 refuses it regardless."
                ),
                priority: if install_public { "critical" } else { "medium" },
            })
        }
        VectorConfigDeliveryCredential::LegacyInstallToken(_) => findings.push(PostureFinding {
            title: "Vector config delivery still accepts the forwarder install token".into(),
            description: format!(
                "{DELIVERY_TOKEN_ENV} is not set, so /api/internal/vector-config/* accepts \
                 VECTOR_AUTH_TOKEN, the token forwarders hold. Any forwarder can then download \
                 rendered Vector configs. Set {DELIVERY_TOKEN_ENV} to a generated value \
                 (`openssl rand -hex 32`) on nano-api, nano-jobs and every Vector config \
                 consumer (install.sh and the Helm chart do this), or set \
                 {DELIVERY_SWITCH_ENV}=off when nothing pulls config over HTTP. nano-api logs \
                 each caller that still uses the install token, with its IP address. From v2.1 \
                 the install token is refused here."
            ),
            priority: if install_public { "critical" } else { "high" },
        }),
        VectorConfigDeliveryCredential::Disabled(DeliveryDisabledReason::PublicDedicatedToken) => {
            findings.push(PostureFinding {
                title: "Vector config delivery is off: its token is a public placeholder".into(),
                description: format!(
                    "{DELIVERY_TOKEN_ENV} is set to a placeholder value, so config delivery is \
                     refused and Vector config consumers cannot pick up new parser versions. \
                     Set it to a generated value (`openssl rand -hex 32`) everywhere it is used."
                ),
                priority: "high",
            });
        }
        VectorConfigDeliveryCredential::Disabled(DeliveryDisabledReason::PublicInstallToken) => {
            findings.push(PostureFinding {
                title: "Vector config delivery is off: only a public install token is configured"
                    .into(),
                description: format!(
                    "{DELIVERY_TOKEN_ENV} is not set and VECTOR_AUTH_TOKEN is a public default \
                     value, so /api/internal/vector-config/* refuses every request: a public \
                     token would let anyone download rendered Vector configs. Vector config \
                     consumers cannot pick up new parser versions or ingest-token changes \
                     until {DELIVERY_TOKEN_ENV} is set to a generated value \
                     (`openssl rand -hex 32`) on nano-api, nano-jobs and every Vector config \
                     consumer (install.sh and the Helm chart do this), or set \
                     {DELIVERY_SWITCH_ENV}=off when nothing pulls config over HTTP."
                ),
                priority: "critical",
            });
        }
        _ => {}
    }

    if inputs.allow_default_keys {
        let dev = inputs.base_url.as_deref().map_or(true, is_loopback_url);
        if !dev {
            findings.push(PostureFinding {
                title: "Built-in development keys are allowed on a non-local deployment".into(),
                description: "NANOSIEM_ALLOW_DEFAULT_KEYS=true lets services fall back to \
                     publicly known development keys (stored-credential encryption, JWT) when \
                     their real key is missing, and BASE_URL is not a localhost address. Remove \
                     NANOSIEM_ALLOW_DEFAULT_KEYS and set NANOSIEM_ENCRYPTION_KEY and JWT_SECRET \
                     to generated values (install.sh does this)."
                    .into(),
                priority: "critical",
            });
        }
    }
    findings
}

/// Log every posture finding once at service start.
pub fn log_posture_at_boot(service: &str) {
    for finding in posture_findings(&PostureInputs::from_env()) {
        if finding.priority == "critical" {
            tracing::error!(service, title = %finding.title, "SECURITY: {}", finding.description);
        } else {
            tracing::warn!(service, title = %finding.title, "SECURITY: {}", finding.description);
        }
    }
}

#[cfg(test)]
#[path = "deployment_posture_tests.rs"]
mod tests;
