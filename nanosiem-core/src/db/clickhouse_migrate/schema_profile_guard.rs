// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5271 (lane L): an UNSET `NANO_SCHEMA_PROFILE` now resolves to OCSF.
//!
//! Before this change an unset value meant UDM (core `from_env_str("")`, the
//! compose `${NANO_SCHEMA_PROFILE:-udm}` fallback). A deployment that never
//! wrote the key is therefore running UDM, and the new default must not flip
//! it: the migrator would create the OCSF tables and every service would read
//! an empty `ocsf_logs`, hiding all existing data.
//!
//! `install.sh`, `nano-upgrade` and nano-main pin `udm` for those deployments
//! before the new default can apply. This guard is the backstop for any path
//! that skips them (a bare `docker compose up` on an old `.env`): before any
//! DDL, the migrator reads which logs table the ClickHouse database already
//! holds and refuses to apply the OCSF default to a UDM install.

use super::types::{ClickHouseMigrateError, ClickHouseMigrator};

/// The logs schema an existing ClickHouse database already holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstalledLogsSchema {
    /// No logs table yet: a fresh install.
    Fresh,
    /// `logs` without `ocsf_logs`: an install running the UDM profile.
    Udm,
    /// `ocsf_logs` exists: an install running the OCSF profile (an OCSF
    /// install also keeps the shared `logs` table).
    Ocsf,
}

/// Classify a database from the names of the tables it holds. Pure, so the
/// decision is unit-testable without ClickHouse.
pub fn classify_installed_logs_schema<S: AsRef<str>>(tables: &[S]) -> InstalledLogsSchema {
    let has = |name: &str| tables.iter().any(|t| t.as_ref() == name);
    if has("ocsf_logs") {
        InstalledLogsSchema::Ocsf
    } else if has("logs") {
        InstalledLogsSchema::Udm
    } else {
        InstalledLogsSchema::Fresh
    }
}

/// Decide whether the migrator may proceed with the raw `NANO_SCHEMA_PROFILE`
/// value against what the database holds. An explicit value is always
/// respected (switching profiles is an operator decision). Only an UNSET value
/// on an existing UDM install is refused, with the fix in the message.
pub fn check_unset_profile_against_install(
    raw_env: &str,
    installed: InstalledLogsSchema,
) -> Result<(), String> {
    if !raw_env.trim().is_empty() || installed != InstalledLogsSchema::Udm {
        return Ok(());
    }
    Err(format!(
        "{env} is unset and this ClickHouse database holds a UDM install (nanosiem.logs \
         without nanosiem.ocsf_logs). An unset {env} now means OCSF, which would point \
         search and detection at an empty table. Set {env}=udm in this deployment's \
         environment (.env for Docker Compose, nano.schemaProfile for Helm; install.sh and \
         `nano upgrade` do this automatically) and start again. Only if this is a NEW OCSF \
         install whose first migration was interrupted, set {env}=ocsf instead. Nothing was \
         changed.",
        env = crate::schema::SCHEMA_PROFILE_ENV
    ))
}

impl ClickHouseMigrator {
    /// The whole guard for one process: `raw_env` is its `NANO_SCHEMA_PROFILE`.
    /// An explicit value returns `Ok(None)` without touching ClickHouse; an
    /// unset one reads the database and returns what it holds, or the refusal.
    /// The migrator runs it before any DDL, and api/jobs/search before serving,
    /// so a service started without the migrator (e.g. `--no-deps`, or a pod
    /// whose migrate step was skipped) refuses with the same fix instead of
    /// reading an absent `ocsf_logs`.
    pub async fn refuse_unset_profile_on_udm_install(
        &self,
        raw_env: &str,
    ) -> Result<Option<InstalledLogsSchema>, String> {
        if !raw_env.trim().is_empty() {
            return Ok(None);
        }
        let installed = self
            .installed_logs_schema()
            .await
            .map_err(|e| format!("detecting the installed logs schema: {e}"))?;
        check_unset_profile_against_install(raw_env, installed)?;
        Ok(Some(installed))
    }

    /// Read which logs schema the target database already holds.
    pub async fn installed_logs_schema(
        &self,
    ) -> Result<InstalledLogsSchema, ClickHouseMigrateError> {
        let database = crate::sql_hygiene::escape_sql_string(&self.database);
        let tables: Vec<String> = self
            .client
            .query(&format!(
                "SELECT name FROM system.tables WHERE database = '{database}' \
                 AND name IN ('logs', 'ocsf_logs')"
            ))
            .fetch_all()
            .await
            .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;
        Ok(classify_installed_logs_schema(&tables))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_fresh_udm_and_ocsf_databases() {
        let none: [&str; 0] = [];
        assert_eq!(classify_installed_logs_schema(&none), InstalledLogsSchema::Fresh);
        assert_eq!(classify_installed_logs_schema(&["logs"]), InstalledLogsSchema::Udm);
        assert_eq!(
            classify_installed_logs_schema(&["logs", "ocsf_logs"]),
            InstalledLogsSchema::Ocsf
        );
        assert_eq!(classify_installed_logs_schema(&["ocsf_logs"]), InstalledLogsSchema::Ocsf);
    }

    #[test]
    fn fresh_install_with_unset_profile_proceeds_as_ocsf() {
        assert!(check_unset_profile_against_install("", InstalledLogsSchema::Fresh).is_ok());
        assert_eq!(
            crate::schema::SchemaId::from_env_str("").unwrap(),
            crate::schema::SchemaId::Ocsf
        );
    }

    #[test]
    fn implicit_udm_install_is_refused_not_flipped() {
        for raw in ["", "  "] {
            let err = check_unset_profile_against_install(raw, InstalledLogsSchema::Udm)
                .unwrap_err();
            assert!(err.contains("NANO_SCHEMA_PROFILE=udm"), "{err}");
            // An interrupted fresh OCSF install looks the same; the message
            // names its fix too instead of steering it onto UDM.
            assert!(err.contains("NANO_SCHEMA_PROFILE=ocsf"), "{err}");
        }
    }

    #[tokio::test]
    async fn explicit_profile_never_probes_clickhouse() {
        // An unreachable URL: any query would fail, so Ok(None) proves the
        // explicit value short-circuits before touching ClickHouse.
        let migrator = ClickHouseMigrator::new(
            clickhouse::Client::default().with_url("http://127.0.0.1:1"),
            "nanosiem".to_string(),
        );
        for raw in ["udm", "ocsf", " OCSF "] {
            assert_eq!(migrator.refuse_unset_profile_on_udm_install(raw).await, Ok(None));
        }
        assert!(migrator.refuse_unset_profile_on_udm_install("").await.is_err());
    }

    #[test]
    fn explicit_profile_is_always_respected() {
        for installed in [
            InstalledLogsSchema::Fresh,
            InstalledLogsSchema::Udm,
            InstalledLogsSchema::Ocsf,
        ] {
            assert!(check_unset_profile_against_install("udm", installed).is_ok());
            assert!(check_unset_profile_against_install("ocsf", installed).is_ok());
        }
        // An unset profile on an install that already runs OCSF is consistent.
        assert!(check_unset_profile_against_install("", InstalledLogsSchema::Ocsf).is_ok());
    }
}
