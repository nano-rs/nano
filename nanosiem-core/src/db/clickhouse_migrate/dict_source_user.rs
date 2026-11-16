// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5470: the dictionary SOURCE identity (`nanosiem_dict`).
//!
//! Every ClickHouse-sourced dictionary reads its source table as a dedicated
//! read-only user instead of the shared app user `nanosiem`. Migration 202,
//! `init.sql` and `ocsf/init.sql` write `USER '{clickhouse_dict_user}'
//! PASSWORD '{clickhouse_dict_password}'`; this module decides what those
//! resolve to.
//!
//! The switch must never leave a server with a dictionary it cannot load: a
//! prevalence CACHE dictionary whose source login fails makes every insert
//! that misses its cache fail (`CACHE_DICTIONARY_UPDATE_FAIL`). So the
//! placeholders resolve to the dictionary identity only when its login is
//! proven on EVERY ClickHouse server (a `remote()` probe per replica with
//! `prefer_localhost_replica = 0`, which authenticates for real), and to the
//! `{clickhouse_self_*}` credentials (what the dictionaries use today)
//! otherwise. [`ClickHouseMigrator::ensure_dictionary_source_user`] re-applies
//! migration 202 on a later run once the identity is ready everywhere: a Helm
//! upgrade runs migrations as a pre-upgrade hook, before ClickHouse has the
//! new user, and a role-split ClickHouse host can be upgraded out of order.

use super::types::{ClickHouseMigrateError, ClickHouseMigrator, Migration};
use std::path::Path;

/// The dictionary identity's user-name placeholder.
pub(crate) const DICT_USER_PLACEHOLDER: &str = "{clickhouse_dict_user}";
/// The dictionary identity's password placeholder.
pub(crate) const DICT_PASSWORD_PLACEHOLDER: &str = "{clickhouse_dict_password}";
/// Migration 202's per-dictionary COMMENT: a fingerprint of the login.
pub(crate) const DICT_FINGERPRINT_PLACEHOLDER: &str = "{clickhouse_dict_fingerprint}";
/// Fingerprint written while the dictionaries read with the self credentials.
pub(crate) const SELF_FINGERPRINT: &str = "nano-dict-source:self";
/// Default dictionary identity (users.d/nanosiem-users.xml).
pub const DICT_SOURCE_DEFAULT_USER: &str = "nanosiem_dict";
/// The migration that (re)defines every ClickHouse-sourced dictionary with the
/// dictionary identity.
pub const DICT_SOURCE_MIGRATION_FILE: &str = "202_dictionary_source_user.sql";
/// Every dictionary migration 202 defines.
pub const DICT_SOURCE_DICTIONARIES: &[&str] = &[
    "hash_prevalence_dict",
    "domain_prevalence_dict",
    "ip_prevalence_dict",
    "ip_geo_attrs_dict",
    "ip_geo_trie_dict",
    "ip_enrichment_dict",
    "ioc_enrichment_dict",
    "custom_ioc_enrichment_dict",
    "custom_enrichment_dict",
    "user_registry_dict",
];
/// A table only the dictionary identity's grants cover. The readiness probe
/// reads zero rows of it through `remote()`, which proves the login, the
/// password and the grant on that server.
const PROBE_TABLE: &str = "user_registry_dict_staging";

/// The configured dictionary identity: `CLICKHOUSE_DICT_USER` (default
/// `nanosiem_dict`) and `CLICKHOUSE_DICT_PASSWORD`. `None` without a password
/// (older .env, dev stacks): the dictionaries keep the self credentials.
pub(crate) fn configured_dict_source() -> Option<(String, String)> {
    let password = std::env::var("CLICKHOUSE_DICT_PASSWORD").ok()?;
    if password.trim().is_empty() {
        return None;
    }
    let user = std::env::var("CLICKHOUSE_DICT_USER")
        .ok()
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| DICT_SOURCE_DEFAULT_USER.to_string());
    Some((user, password))
}

/// Resolve the dictionary placeholders: to the (escaped) dictionary
/// credentials when `ready` holds them, else to the `{clickhouse_self_*}`
/// placeholders, which the self-var substitution then resolves exactly as
/// before NAN-5470. Must run BEFORE `substitute_clickhouse_self_vars`.
pub(crate) fn substitute_dict_source_vars(sql: &str, ready: Option<&(String, String)>) -> String {
    match ready {
        Some((user, password)) => sql
            .replace(DICT_USER_PLACEHOLDER, &ClickHouseMigrator::escape_for_string_literal(user))
            .replace(
                DICT_PASSWORD_PLACEHOLDER,
                &ClickHouseMigrator::escape_for_string_literal(password),
            )
            .replace(DICT_FINGERPRINT_PLACEHOLDER, &credentials_fingerprint(user, password)),
        None => sql
            .replace(DICT_USER_PLACEHOLDER, "{clickhouse_self_user}")
            .replace(DICT_PASSWORD_PLACEHOLDER, "{clickhouse_self_password}")
            .replace(DICT_FINGERPRINT_PLACEHOLDER, SELF_FINGERPRINT),
    }
}

/// NAN-5470: what migration 202 writes into each dictionary's COMMENT for a
/// login: 16 hex characters of SHA-256 over user and password. Identifies a
/// credential change without revealing anything about the password.
pub(crate) fn credentials_fingerprint(user: &str, password: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{user}\0{password}").as_bytes());
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("nano-dict-source:{hex}")
}

/// One `remote()` / `remoteSecure()` readiness probe (reads zero rows).
pub(crate) fn readiness_probe_sql(
    host: &str,
    port: u16,
    database: &str,
    user: &str,
    password: &str,
    secure: bool,
) -> String {
    let function = if secure { "remoteSecure" } else { "remote" };
    let address = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    format!(
        "SELECT count() FROM {function}('{address}', '{db}', '{table}', '{user}', '{password}') \
         WHERE 0 SETTINGS prefer_localhost_replica = 0",
        address = ClickHouseMigrator::escape_for_string_literal(&address),
        db = ClickHouseMigrator::escape_for_string_literal(database),
        table = PROBE_TABLE,
        user = ClickHouseMigrator::escape_for_string_literal(user),
        password = ClickHouseMigrator::escape_for_string_literal(password),
    )
}

#[derive(Debug, clickhouse::Row, serde::Deserialize)]
struct ReplicaEndpoint {
    host_name: String,
    port: u16,
}

#[derive(Debug, clickhouse::Row, serde::Deserialize)]
struct DictionaryState {
    name: String,
    comment: String,
    last_exception: String,
}

/// Whether a dictionary must be re-pointed: its COMMENT is not the current
/// login's fingerprint (an older definition, init.sql's, or a changed
/// password), or its last load failed authenticating.
pub(crate) fn dictionary_is_stale(comment: &str, last_exception: &str, fingerprint: &str) -> bool {
    comment != fingerprint
        || last_exception.contains("AUTHENTICATION_FAILED")
        || last_exception.contains("Code: 516")
}

impl ClickHouseMigrator {
    /// Re-check whether the dictionary identity is usable on every ClickHouse
    /// server and remember the answer for this run's substitutions. Once ready
    /// it stays ready for the rest of the run; until then every call probes
    /// again (a fresh install creates the probed table in init.sql).
    pub(super) async fn refresh_dict_source_readiness(&mut self) {
        if self.dict_source.is_some() {
            return;
        }
        let Some(credentials) = configured_dict_source() else {
            return;
        };
        if self.is_cloud == Some(true) {
            return;
        }
        match self.dict_source_ready_everywhere(&credentials).await {
            Ok(()) => {
                tracing::info!(
                    user = %credentials.0,
                    "NAN-5470: dictionary source identity is ready on every ClickHouse server"
                );
                self.dict_source = Some(credentials);
            }
            Err(reason) => {
                tracing::info!(
                    user = %credentials.0,
                    %reason,
                    "NAN-5470: dictionary source identity not ready yet; dictionaries keep the \
                     self credentials (re-checked on every migrate)"
                );
            }
        }
    }

    async fn dict_source_ready_everywhere(&mut self, credentials: &(String, String)) -> Result<(), String> {
        let (user, password) = credentials;
        let secure = matches!(
            std::env::var("CLICKHOUSE_SELF_SECURE").ok().as_deref(),
            Some("1") | Some("true") | Some("TRUE") | Some("True")
        );
        let cluster = self.detect_cluster().await.map_err(|e| e.to_string())?;
        let endpoints: Vec<(String, u16)> = match cluster {
            Some(cluster) => {
                let rows: Vec<ReplicaEndpoint> = self
                    .client
                    .query("SELECT host_name, port FROM system.clusters WHERE cluster = ?")
                    .bind(&cluster)
                    .fetch_all()
                    .await
                    .map_err(|e| format!("listing the replicas of cluster '{cluster}': {e}"))?;
                if rows.is_empty() {
                    return Err(format!("cluster '{cluster}' lists no replica"));
                }
                rows.into_iter().map(|r| (r.host_name, r.port)).collect()
            }
            None => {
                // Single server: the dictionaries self-connect through
                // CLICKHOUSE_SELF_HOST / _PORT, so probe exactly that.
                let host = std::env::var("CLICKHOUSE_SELF_HOST").unwrap_or_else(|_| "localhost".into());
                let port = std::env::var("CLICKHOUSE_SELF_PORT")
                    .ok()
                    .and_then(|p| p.parse::<u16>().ok())
                    .unwrap_or(9000);
                vec![(host, port)]
            }
        };
        for (host, port) in endpoints {
            let sql = readiness_probe_sql(&host, port, &self.database, user, password, secure);
            self.client
                .query(&sql)
                .fetch_one::<u64>()
                .await
                .map_err(|e| format!("{host}:{port}: {}", redact(&e.to_string(), password)))?;
        }
        Ok(())
    }

    /// NAN-5470: point every ClickHouse-sourced dictionary at the dictionary
    /// identity once it is ready on every server, by re-applying migration 202
    /// (its `CREATE OR REPLACE DICTIONARY` statements are idempotent). A no-op
    /// when no dictionary identity is configured, when it is not ready yet, or
    /// when every dictionary already uses it. Returns whether it re-applied.
    pub async fn ensure_dictionary_source_user(
        &mut self,
        migrations_dir: &Path,
    ) -> Result<bool, ClickHouseMigrateError> {
        let is_cloud = self.detect_cloud().await?;
        if is_cloud {
            return Ok(false);
        }
        self.refresh_dict_source_readiness().await;
        let Some((user, password)) = self.dict_source.clone() else {
            return Ok(false);
        };
        let fingerprint = credentials_fingerprint(&user, &password);
        let names = DICT_SOURCE_DICTIONARIES
            .iter()
            .map(|n| format!("'{n}'"))
            .collect::<Vec<_>>()
            .join(", ");
        let rows: Vec<DictionaryState> = self
            .client
            .query(&format!(
                "SELECT name, comment, last_exception FROM system.dictionaries \
                 WHERE database = ? AND name IN ({names})"
            ))
            .bind(&self.database)
            .fetch_all()
            .await
            .map_err(|e| ClickHouseMigrateError::ClickHouse(format!("reading dictionary state: {e}")))?;
        let stale: Vec<&str> = rows
            .iter()
            .filter(|r| dictionary_is_stale(&r.comment, &r.last_exception, &fingerprint))
            .map(|r| r.name.as_str())
            .collect();
        if stale.is_empty() {
            return Ok(false);
        }
        let path = migrations_dir.join(DICT_SOURCE_MIGRATION_FILE);
        let sql = std::fs::read_to_string(&path).map_err(|e| {
            ClickHouseMigrateError::ClickHouse(format!("reading {}: {e}", path.display()))
        })?;
        tracing::info!(
            user = %user,
            dictionaries = ?stale,
            "NAN-5470: re-pointing dictionary sources at the dictionary identity (re-applying {})",
            DICT_SOURCE_MIGRATION_FILE
        );
        let migration = Migration {
            version: "202".to_string(),
            name: "dictionary_source_user".to_string(),
            filename: DICT_SOURCE_MIGRATION_FILE.to_string(),
            sql,
        };
        let cluster = self.detect_cluster().await?;
        self.apply_migration(&migration, is_cloud, cluster.as_deref()).await?;
        Ok(true)
    }
}

/// Never echo the probed password back in a log line.
fn redact(message: &str, password: &str) -> String {
    if password.is_empty() {
        message.to_string()
    } else {
        message.replace(password, "[HIDDEN]")
    }
}
