// SPDX-License-Identifier: AGPL-3.0-or-later

//! The single resolution of the deployment's log-query backend and tenant
//! schema profile (NAN-3491).
//!
//! The ClickHouse log backend and the UDM tenant schema were removed. Every
//! process now serves logs from the object lake under canonical OCSF, so the
//! two environment variables that used to select them only have one valid
//! value each, and leaving them unset selects it:
//!
//! | variable                 | unset / empty | accepted | anything else          |
//! |--------------------------|---------------|----------|------------------------|
//! | `NANO_LOG_QUERY_BACKEND` | lake          | `lake`   | boot error             |
//! | `NANO_SCHEMA_PROFILE`    | OCSF          | `ocsf`   | boot error (incl. udm) |
//!
//! A legacy value (`clickhouse`, `shadow`, `udm`) is never silently converted:
//! it names a deployment this build can no longer serve, so the boot paths of
//! api, search and jobs refuse to start with [`LEGACY_BACKEND_REMOVED`].
//! Code outside the boot path asks [`log_query_backend_is_lake`], which agrees
//! with the boot decision for every process that managed to boot.

use super::{SchemaId, LOG_QUERY_BACKEND_ENV, SCHEMA_PROFILE_ENV};

/// Operator-facing explanation attached to every legacy-value refusal.
pub const LEGACY_BACKEND_REMOVED: &str = "the ClickHouse/UDM edition was removed; \
     ClickHouse deployments stay frozen at <=0.1.702, maintained only from branch \
     legacy/clickhouse (unsupported)";

/// The log-query backend. Only the object lake remains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogQueryBackend {
    /// Logs are read from the object lake (tenant-pinned query workers or the
    /// lean lake cell).
    Lake,
}

/// The resolved runtime profile of this process: backend plus tenant schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeProfile {
    pub backend: LogQueryBackend,
    pub schema: SchemaId,
}

fn normalized(raw: Option<&str>) -> String {
    raw.unwrap_or_default().trim().to_ascii_lowercase()
}

/// Resolve the log-query backend from a raw `NANO_LOG_QUERY_BACKEND` value.
/// Pure (env-free) so it is unit-testable.
pub fn log_query_backend_from_value(raw: Option<&str>) -> Result<LogQueryBackend, String> {
    match normalized(raw).as_str() {
        "" | "lake" => Ok(LogQueryBackend::Lake),
        other => Err(format!(
            "unsupported {LOG_QUERY_BACKEND_ENV}={other:?} (expected \"lake\" or unset): \
             {LEGACY_BACKEND_REMOVED}"
        )),
    }
}

/// Resolve the tenant schema from a raw `NANO_SCHEMA_PROFILE` value. Pure
/// (env-free) so it is unit-testable.
pub fn schema_id_from_value(raw: Option<&str>) -> Result<SchemaId, String> {
    match normalized(raw).as_str() {
        "" | "ocsf" => Ok(SchemaId::Ocsf),
        other => Err(format!(
            "unsupported {SCHEMA_PROFILE_ENV}={other:?} (expected \"ocsf\" or unset): \
             {LEGACY_BACKEND_REMOVED}"
        )),
    }
}

/// Resolve the full runtime profile from raw env values. Pure (env-free).
pub fn resolve_runtime_profile(
    schema_raw: Option<&str>,
    backend_raw: Option<&str>,
) -> Result<RuntimeProfile, String> {
    Ok(RuntimeProfile {
        backend: log_query_backend_from_value(backend_raw)?,
        schema: schema_id_from_value(schema_raw)?,
    })
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Env-resolving wrapper for [`log_query_backend_from_value`].
pub fn log_query_backend() -> Result<LogQueryBackend, String> {
    log_query_backend_from_value(env_value(LOG_QUERY_BACKEND_ENV).as_deref())
}

/// Env-resolving wrapper for [`schema_id_from_value`].
pub fn runtime_schema_id() -> Result<SchemaId, String> {
    schema_id_from_value(env_value(SCHEMA_PROFILE_ENV).as_deref())
}

/// Env-resolving wrapper for [`resolve_runtime_profile`]. The api, search and
/// jobs boot paths call this and refuse to start on `Err`.
pub fn runtime_profile_from_env() -> Result<RuntimeProfile, String> {
    resolve_runtime_profile(
        env_value(SCHEMA_PROFILE_ENV).as_deref(),
        env_value(LOG_QUERY_BACKEND_ENV).as_deref(),
    )
}

/// Whether log reads are served by the lake: `true` when
/// `NANO_LOG_QUERY_BACKEND` is unset, empty or `lake`.
///
/// For readers outside the boot path. A legacy value answers `false` so such a
/// reader never turns a misconfiguration into lake traffic, but no booted
/// api/search/jobs process can observe it: their boot refuses that value.
pub fn log_query_backend_is_lake() -> bool {
    log_query_backend().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_or_empty_resolves_to_lake_and_ocsf() {
        let expected = RuntimeProfile {
            backend: LogQueryBackend::Lake,
            schema: SchemaId::Ocsf,
        };
        assert_eq!(resolve_runtime_profile(None, None).unwrap(), expected);
        assert_eq!(
            resolve_runtime_profile(Some(""), Some("  ")).unwrap(),
            expected
        );
    }

    #[test]
    fn explicit_lake_and_ocsf_resolve_unchanged() {
        // The hosted hosted-shared deployment sets exactly these.
        let expected = RuntimeProfile {
            backend: LogQueryBackend::Lake,
            schema: SchemaId::Ocsf,
        };
        assert_eq!(
            resolve_runtime_profile(Some("ocsf"), Some("lake")).unwrap(),
            expected
        );
        assert_eq!(
            resolve_runtime_profile(Some(" OCSF "), Some("LAKE")).unwrap(),
            expected
        );
    }

    #[test]
    fn legacy_backends_are_refused_not_converted() {
        for legacy in ["clickhouse", "shadow", "ClickHouse", "bogus"] {
            let error = log_query_backend_from_value(Some(legacy)).unwrap_err();
            assert!(error.contains(LOG_QUERY_BACKEND_ENV), "{error}");
            assert!(error.contains("legacy/clickhouse"), "{error}");
            assert!(resolve_runtime_profile(Some("ocsf"), Some(legacy)).is_err());
        }
    }

    #[test]
    fn udm_schema_is_refused_not_converted() {
        for legacy in ["udm", "UDM", "splunk"] {
            let error = schema_id_from_value(Some(legacy)).unwrap_err();
            assert!(error.contains(SCHEMA_PROFILE_ENV), "{error}");
            assert!(error.contains("legacy/clickhouse"), "{error}");
            assert!(resolve_runtime_profile(Some(legacy), Some("lake")).is_err());
            assert!(resolve_runtime_profile(Some(legacy), None).is_err());
        }
    }
}
