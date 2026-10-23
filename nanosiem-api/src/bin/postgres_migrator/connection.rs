// SPDX-License-Identifier: AGPL-3.0-or-later

//! Optional file-backed migration credentials. Secret bytes never enter a
//! shell-composed URL, command arguments, or a serializable configuration.

use anyhow::{bail, ensure, Context, Result};
use nanosiem_core::db::{pool::DatabaseError, Database};
use sqlx::{
    postgres::{PgConnectOptions, PgSslMode},
    ConnectOptions, PgPool,
};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

const PASSWORD_FILE: &str = "NANOSIEM_MIGRATOR_PASSWORD_FILE";
const FILE_FIELDS: [&str; 6] = [
    "NANOSIEM_MIGRATOR_SECRET_ROOT",
    "NANOSIEM_MIGRATOR_DATABASE_HOST",
    "NANOSIEM_MIGRATOR_DATABASE_USER",
    "NANOSIEM_MIGRATOR_DATABASE_NAME",
    "NANOSIEM_MIGRATOR_DATABASE_PORT",
    "NANOSIEM_MIGRATOR_CA_FILE",
];
const AMBIENT_PG_FIELDS: [&str; 12] = [
    "PGHOST",
    "PGHOSTADDR",
    "PGPORT",
    "PGUSER",
    "PGDATABASE",
    "PGPASSWORD",
    "PGSSLROOTCERT",
    "PGSSLCERT",
    "PGSSLKEY",
    "PGSSLMODE",
    "PGOPTIONS",
    "PGPASSFILE",
];

// Intentionally no Debug: the legacy URL can contain a password.
pub enum MigrationConnection {
    LegacyUrl(Zeroizing<String>),
    PrivateFile(PrivateFileConnection),
}

pub struct PrivateFileConnection {
    password_file: PathBuf,
    secret_root: PathBuf,
    host: String,
    user: String,
    database: String,
    port: u16,
    ca_file: PathBuf,
}

impl MigrationConnection {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => bail!("migration connection environment contains invalid text"),
        })
    }

    fn from_lookup(mut get: impl FnMut(&str) -> Result<Option<String>>) -> Result<Self> {
        let url = get("DATABASE_URL")?.map(Zeroizing::new);
        let password_file = get(PASSWORD_FILE)?;
        let mut fields = Vec::new();
        for name in FILE_FIELDS {
            fields.push(get(name)?);
        }
        if password_file.is_none() && fields.iter().all(Option::is_none) {
            return Ok(Self::LegacyUrl(url.context(
                "DATABASE_URL or explicit file-backed migration configuration is required",
            )?));
        }
        ensure!(
            url.is_none(),
            "DATABASE_URL and file-backed migration configuration cannot be combined"
        );
        for name in AMBIENT_PG_FIELDS {
            ensure!(
                get(name)?.is_none(),
                "ambient PG connection settings are not allowed in file-backed migration mode"
            );
        }
        let password_file =
            PathBuf::from(password_file.context("migration password file is required")?);
        ensure!(
            fields.iter().all(Option::is_some),
            "file-backed migration configuration is incomplete"
        );
        let mut fields = fields.into_iter().map(Option::unwrap);
        let secret_root = PathBuf::from(fields.next().unwrap());
        let host = fields.next().unwrap();
        let user = fields.next().unwrap();
        let database = fields.next().unwrap();
        let port: u16 = fields
            .next()
            .unwrap()
            .parse()
            .context("invalid migration database port")?;
        let ca_file = PathBuf::from(fields.next().unwrap());
        ensure!(
            password_file.is_absolute()
                && secret_root.is_absolute()
                && password_file != secret_root
                && ca_file.is_absolute(),
            "migration credential and CA paths must be absolute"
        );
        ensure!(
            valid_host(&host)
                && valid_login_user(&user, &host, port)
                && valid_identifier(&database)
                && port > 0,
            "invalid file-backed migration database identity"
        );
        Ok(Self::PrivateFile(PrivateFileConnection {
            password_file,
            secret_root,
            host,
            user,
            database,
            port,
            ca_file,
        }))
    }

    pub async fn connect(self) -> Result<PgPool> {
        match self {
            Self::LegacyUrl(url) => Ok(connect_legacy_with_retry(
                || Database::connect(&url),
                tokio::time::sleep,
            )
            .await
            .context("connecting to PostgreSQL for migrations")?
            .pool()
            .clone()),
            Self::PrivateFile(config) => {
                let password =
                    read_private_password(&config.password_file, &config.secret_root).await?;
                // Do not consult ~/.pgpass. Every endpoint/TLS/credential field
                // is explicit; file mode rejects ambient PG connection settings.
                let options = PgConnectOptions::new_without_pgpass()
                    .host(&config.host)
                    .port(config.port)
                    .username(&config.user)
                    .database(&config.database)
                    .password(&password)
                    .ssl_mode(PgSslMode::VerifyFull)
                    .ssl_root_cert(&config.ca_file)
                    .application_name("nano-postgres-migrator")
                    .disable_statement_logging();
                Ok(nanosiem_core::db::connection_budget::pool_options(1)
                    .acquire_timeout(Duration::from_secs(30))
                    .connect_lazy_with(options))
            }
        }
    }
}

// A fresh Job can reach DNS before its egress policy reaches the node. Retry
// only connection transport failures, before the caller can run migration SQL.
// Authentication, TLS, configuration and database errors remain immediate failures.
async fn connect_legacy_with_retry<T, F, Fut, S, Sleep>(
    mut connect: F,
    mut sleep: S,
) -> std::result::Result<T, DatabaseError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, DatabaseError>>,
    S: FnMut(Duration) -> Sleep,
    Sleep: std::future::Future<Output = ()>,
{
    const MAX_ATTEMPTS: u32 = 3;
    let mut attempt = 1;
    loop {
        match connect().await {
            Ok(connection) => return Ok(connection),
            Err(error) if attempt < MAX_ATTEMPTS && retryable_connection_error(&error) => {
                let delay = Duration::from_secs(2 * u64::from(attempt));
                // No URL, credentials, or raw error text in retry diagnostics.
                tracing::warn!(
                    attempt,
                    max_attempts = MAX_ATTEMPTS,
                    retry_delay_secs = delay.as_secs(),
                    "Migration database transport unavailable before SQL; retrying connection"
                );
                sleep(delay).await;
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

fn retryable_connection_error(error: &DatabaseError) -> bool {
    let DatabaseError::ConnectionError(error) = error else {
        return false;
    };
    match error {
        sqlx::Error::PoolTimedOut => true,
        sqlx::Error::Io(error) => {
            matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::AddrNotAvailable
            ) || error.to_string().starts_with(
                "failed to lookup address information: Temporary failure in name resolution",
            )
        }
        _ => false,
    }
}

#[cfg(test)]
mod connection_retry_tests {
    use super::*;
    use std::{collections::VecDeque, future::ready, io};

    fn transport() -> DatabaseError {
        sqlx::Error::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "temporary transport failure",
        ))
        .into()
    }

    #[test]
    fn temporary_dns_retries_but_permanent_lookup_failure_does_not() {
        let dns =
            |message| DatabaseError::ConnectionError(sqlx::Error::Io(io::Error::other(message)));
        assert!(retryable_connection_error(&dns(
            "failed to lookup address information: Temporary failure in name resolution"
        )));
        assert!(!retryable_connection_error(&dns(
            "failed to lookup address information: Name or service not known"
        )));
    }

    #[tokio::test]
    async fn recovers_before_sql_with_bounded_backoff() {
        let mut results = VecDeque::from([Err(transport()), Err(transport()), Ok(())]);
        let mut delays = Vec::new();
        connect_legacy_with_retry(
            || ready(results.pop_front().unwrap()),
            |delay| {
                delays.push(delay);
                ready(())
            },
        )
        .await
        .unwrap();
        assert!(results.is_empty());
        assert_eq!(delays, [Duration::from_secs(2), Duration::from_secs(4)]);
    }

    #[tokio::test]
    async fn transport_exhaustion_returns_the_last_error() {
        let mut attempts = 0;
        let mut delays = Vec::new();
        let result: std::result::Result<(), _> = connect_legacy_with_retry(
            || {
                attempts += 1;
                ready(Err(transport()))
            },
            |delay| {
                delays.push(delay);
                ready(())
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(DatabaseError::ConnectionError(sqlx::Error::Io(_)))
        ));
        assert_eq!(attempts, 3);
        assert_eq!(delays.len(), 2);
    }

    #[tokio::test]
    async fn pool_connection_timeout_can_recover() {
        let mut results = VecDeque::from([
            Err(DatabaseError::ConnectionError(sqlx::Error::PoolTimedOut)),
            Ok(()),
        ]);
        connect_legacy_with_retry(|| ready(results.pop_front().unwrap()), |_| ready(()))
            .await
            .unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn non_transport_errors_never_retry() {
        for error in [
            DatabaseError::ConnectionError(sqlx::Error::Tls(Box::new(io::Error::other(
                "invalid certificate",
            )))),
            DatabaseError::ConnectionError(sqlx::Error::Configuration(Box::new(io::Error::other(
                "invalid configuration",
            )))),
            DatabaseError::ConnectionError(sqlx::Error::Protocol("authentication failure".into())),
            DatabaseError::ConnectionError(sqlx::Error::Io(io::Error::from(
                io::ErrorKind::PermissionDenied,
            ))),
            DatabaseError::ConnectionError(sqlx::Error::Io(io::Error::from(
                io::ErrorKind::NotFound,
            ))),
            DatabaseError::HealthCheckError("not a connection failure".into()),
        ] {
            let mut error = Some(error);
            let mut delays = Vec::new();
            let result: std::result::Result<(), _> = connect_legacy_with_retry(
                || ready(Err(error.take().expect("fatal error must not retry"))),
                |delay| {
                    delays.push(delay);
                    ready(())
                },
            )
            .await;
            assert!(result.is_err());
            assert!(delays.is_empty());
        }
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_lowercase() || (index > 0 && byte.is_ascii_digit())
        })
}

fn valid_login_user(value: &str, host: &str, port: u16) -> bool {
    if valid_identifier(value) {
        return true;
    }
    // PlanetScale routes the startup login to a branch using role.branch.
    // Preserve that suffix; stripping it could select a different database.
    let Some((role, branch)) = value.split_once('.') else {
        return false;
    };
    valid_identifier(role)
        && (8..=64).contains(&branch.len())
        && branch
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && (host.ends_with(".horizon.psdb.cloud") || host.ends_with(".pg.psdb.cloud"))
        && port == 5432
}

fn valid_host(value: &str) -> bool {
    if value.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

#[cfg(unix)]
async fn read_private_password(path: &Path, root: &Path) -> Result<Zeroizing<String>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use tokio::io::AsyncReadExt;
    let root = tokio::fs::canonicalize(root)
        .await
        .context("migration secret root is unavailable")?;
    let target = tokio::fs::canonicalize(path)
        .await
        .context("migration password file is unavailable")?;
    ensure!(
        target.starts_with(&root) && target != root,
        "migration password file escapes its trusted root"
    );
    let mut directory = target.parent().context("migration secret has no parent")?;
    loop {
        let metadata = tokio::fs::metadata(directory)
            .await
            .context("migration secret directory is unavailable")?;
        ensure!(
            metadata.is_dir() && metadata.permissions().mode() & 0o022 == 0,
            "migration secret directory is writable by another principal"
        );
        if directory == root {
            break;
        }
        directory = directory
            .parent()
            .context("migration secret directory escapes its root")?;
        ensure!(
            directory.starts_with(&root),
            "migration secret directory escapes its root"
        );
    }
    let before = tokio::fs::metadata(&target)
        .await
        .context("migration secret metadata is unavailable")?;
    ensure!(
        before.is_file()
            && matches!(before.permissions().mode() & 0o7777, 0o400 | 0o600)
            && (1..=4096).contains(&before.len()),
        "migration password file must be bounded and mode 0400 or 0600"
    );
    let file = tokio::fs::File::open(&target)
        .await
        .context("migration password file cannot be opened")?;
    let same = |metadata: &std::fs::Metadata| {
        metadata.dev() == before.dev()
            && metadata.ino() == before.ino()
            && metadata.len() == before.len()
            && metadata.mtime() == before.mtime()
            && metadata.mtime_nsec() == before.mtime_nsec()
            && metadata.permissions().mode() == before.permissions().mode()
    };
    ensure!(
        same(&file.metadata().await?),
        "migration password file changed during open"
    );
    let mut reader = file.take(4097);
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut bytes)
        .await
        .context("migration password file cannot be read")?;
    ensure!(
        same(&reader.get_ref().metadata().await?) && same(&tokio::fs::metadata(&target).await?),
        "migration password file changed during read"
    );
    ensure!(
        (1..=4096).contains(&bytes.len()) && !bytes.contains(&0),
        "invalid migration password file contents"
    );
    // Preserve exact bytes, including spaces and URL-reserved characters.
    let value = std::str::from_utf8(&bytes).context("migration password is not valid UTF-8")?;
    Ok(Zeroizing::new(value.to_owned()))
}

#[cfg(not(unix))]
async fn read_private_password(_path: &Path, _root: &Path) -> Result<Zeroizing<String>> {
    bail!("mode-private migration credential files require a Unix platform")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn file_config() -> BTreeMap<&'static str, String> {
        [
            (PASSWORD_FILE, "/private/password"),
            (FILE_FIELDS[0], "/private"),
            (FILE_FIELDS[1], "postgres.group-db.svc.cluster.local"),
            (FILE_FIELDS[2], "postgres"),
            (FILE_FIELDS[3], "nanosiem_shared"),
            (FILE_FIELDS[4], "5432"),
            (FILE_FIELDS[5], "/ca/ca.crt"),
        ]
        .into_iter()
        .map(|(key, value)| (key, value.to_owned()))
        .collect()
    }
    fn parse(values: &BTreeMap<&str, String>) -> Result<MigrationConnection> {
        MigrationConnection::from_lookup(|key| Ok(values.get(key).cloned()))
    }
    #[test]
    fn preserves_explicit_legacy_url_mode() {
        let values = BTreeMap::from([("DATABASE_URL", "postgres://localhost/fixture".to_owned())]);
        assert!(matches!(
            parse(&values).unwrap(),
            MigrationConnection::LegacyUrl(_)
        ));
        assert!(parse(&BTreeMap::new()).is_err());
    }
    #[test]
    fn requires_complete_unambiguous_file_configuration() {
        assert!(matches!(
            parse(&file_config()).unwrap(),
            MigrationConnection::PrivateFile(_)
        ));
        let mut values = file_config();
        values.insert(
            "DATABASE_URL",
            "postgres://should-not-be-used/fixture".to_owned(),
        );
        assert!(parse(&values).is_err());
        for key in [PASSWORD_FILE].into_iter().chain(FILE_FIELDS) {
            let mut values = file_config();
            values.remove(key);
            assert!(parse(&values).is_err());
        }
        for key in AMBIENT_PG_FIELDS {
            let mut values = file_config();
            values.insert(key, "ignored-settings-are-unsafe".to_owned());
            assert!(parse(&values).is_err());
        }
    }
    #[test]
    fn preserves_planetscale_branch_login_only_for_managed_endpoints() {
        let mut values = file_config();
        values.insert(FILE_FIELDS[1], "cluster.horizon.psdb.cloud".to_owned());
        values.insert(FILE_FIELDS[2], "postgres.testbranch123".to_owned());
        let MigrationConnection::PrivateFile(parsed) = parse(&values).unwrap() else {
            panic!("expected private-file connection");
        };
        assert_eq!(parsed.user, "postgres.testbranch123");
        for user in [
            "postgres.",
            "postgres.short",
            "postgres.branch.with.dot",
            "postgres.branch_bad",
        ] {
            values.insert(FILE_FIELDS[2], user.to_owned());
            assert!(parse(&values).is_err());
        }
        values.insert(FILE_FIELDS[2], "postgres.testbranch123".to_owned());
        values.insert(FILE_FIELDS[1], "postgres.internal".to_owned());
        assert!(parse(&values).is_err());
        values.insert(FILE_FIELDS[1], "cluster.horizon.psdb.cloud".to_owned());
        values.insert(FILE_FIELDS[4], "5433".to_owned());
        assert!(parse(&values).is_err());
    }
    #[test]
    fn rejects_socket_urls_invalid_identities_and_relative_paths() {
        for (key, value) in [
            (FILE_FIELDS[1], "/var/run/postgresql"),
            (FILE_FIELDS[1], "https://db"),
            (FILE_FIELDS[2], "postgres' injected"),
            (FILE_FIELDS[3], "db/name"),
            (FILE_FIELDS[4], "0"),
            (FILE_FIELDS[4], "65536"),
            (PASSWORD_FILE, "relative"),
            (FILE_FIELDS[5], "relative-ca"),
        ] {
            let mut values = file_config();
            values.insert(key, value.to_owned());
            assert!(parse(&values).is_err());
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn private_reader_preserves_password_bytes_and_rejects_unsafe_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("password");
        let password = "fixture password @:/?#%& + unicode-é\n";
        tokio::fs::write(&path, password).await.unwrap();
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();
        assert_eq!(
            &*read_private_password(&path, root.path()).await.unwrap(),
            password
        );
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .await
            .unwrap();
        assert!(read_private_password(&path, root.path()).await.is_err());
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();
        tokio::fs::write(&path, vec![b'x'; 4097]).await.unwrap();
        assert!(read_private_password(&path, root.path()).await.is_err());
        tokio::fs::write(&path, b"nul\0byte").await.unwrap();
        assert!(read_private_password(&path, root.path()).await.is_err());
        let outside = tempfile::NamedTempFile::new().unwrap();
        let link = root.path().join("escape");
        symlink(outside.path(), &link).unwrap();
        assert!(read_private_password(&link, root.path()).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires scripts/validate-postgres-migrator-file-credentials.mjs disposable TLS fixture"]
    async fn file_credentials_use_tls_and_reject_wrong_password_and_ca() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::env::var("NANO_MIGRATOR_LOCAL_FIXTURE").as_deref(),
            Ok("1")
        );
        let config = match MigrationConnection::from_env().unwrap() {
            MigrationConnection::PrivateFile(config) => config,
            _ => panic!("fixture must use file-backed credentials"),
        };
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.user, "migrator_fixture");
        assert_eq!(config.database, "nano_migrator_fixture");
        assert!(config.port > 1024);
        let wrong_password = config.secret_root.join("wrong-password");
        let pool = MigrationConnection::PrivateFile(config)
            .connect()
            .await
            .unwrap();
        let secure: bool =
            sqlx::query_scalar("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(secure);
        let version: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::int")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!((180000..190000).contains(&version));
        pool.close().await;

        let mut file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&wrong_password)
            .await
            .unwrap();
        use tokio::io::AsyncWriteExt;
        file.write_all(b"not-the-fixture-password").await.unwrap();
        file.shutdown().await.unwrap();
        tokio::fs::set_permissions(&wrong_password, std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();
        let mut bad = match MigrationConnection::from_env().unwrap() {
            MigrationConnection::PrivateFile(config) => config,
            _ => unreachable!(),
        };
        bad.password_file = wrong_password;
        assert!(MigrationConnection::PrivateFile(bad)
            .connect()
            .await
            .is_err());
        let mut bad_ca = match MigrationConnection::from_env().unwrap() {
            MigrationConnection::PrivateFile(config) => config,
            _ => unreachable!(),
        };
        bad_ca.ca_file = PathBuf::from(std::env::var("NANO_MIGRATOR_TEST_WRONG_CA_FILE").unwrap());
        assert!(MigrationConnection::PrivateFile(bad_ca)
            .connect()
            .await
            .is_err());
    }
}
