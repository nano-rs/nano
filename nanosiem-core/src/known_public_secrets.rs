// SPDX-License-Identifier: AGPL-3.0-or-later

//! Secret values that are public because nano itself shipped them.
//!
//! Every literal that has ever appeared as a default or example value for a
//! deployment secret, in a compose file, `.env.example`, the docs or a dev
//! script, is public. An install running on one of them has no secret at all.
//! This is the single list every consumer checks:
//!
//! - JWT signing (`auth::token::TokenConfig`, the API's auth state) refuses to
//!   boot on a known JWT value;
//! - the credential key ring (`crypto::keyring`) refuses a known key as the
//!   active key and accepts it only as explicit decrypt-only legacy material;
//! - the Vector install token and the config-delivery token are reported (and,
//!   from v2.1, refused) when they hold a known value.
//!
//! `config/known-public-secrets.txt` is the same list for shell tooling
//! (`scripts/lib/generated-secrets.sh` treats these values as unset and
//! regenerates them on install/upgrade). A unit test keeps the two identical.
//!
//! Adding a value is always safe for nano's own installs: install.sh never
//! writes these values, so only hand-made configurations that copied an example
//! are affected, and those are exactly the installs that must change.

/// What a known public value was shipped as. Values are matched per kind, so a
/// placeholder shared by every kind (e.g. `CHANGE_ME`) is listed under each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretKind {
    /// `JWT_SECRET`.
    Jwt,
    /// `NANOSIEM_ENCRYPTION_KEY` (plain-string form).
    EncryptionKey,
    /// `VECTOR_AUTH_TOKEN`, the forwarder install token.
    VectorInstallToken,
    /// `NANO_VECTOR_CONFIG_DELIVERY_TOKEN`.
    VectorConfigDeliveryToken,
    /// PostgreSQL / ClickHouse passwords (`POSTGRES_PASSWORD`,
    /// `CLICKHOUSE_*PASSWORD`). Reported, never rotated automatically: the
    /// databases keep the password their data was initialised with.
    DbPassword,
}

/// The env vars that carry a database password.
pub const DB_PASSWORD_ENV_VARS: &[&str] = &[
    "POSTGRES_PASSWORD",
    "CLICKHOUSE_PASSWORD",
    "CLICKHOUSE_ADMIN_PASSWORD",
    "CLICKHOUSE_VECTOR_PASSWORD",
    "CLICKHOUSE_INGEST_PASSWORD",
    "CLICKHOUSE_RAWSQL_PASSWORD",
    "CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD",
];

impl SecretKind {
    /// The environment variable that carries this secret (`None` for the
    /// database passwords, which have several: see [`DB_PASSWORD_ENV_VARS`]).
    pub fn env_var(self) -> Option<&'static str> {
        match self {
            Self::Jwt => Some("JWT_SECRET"),
            Self::EncryptionKey => Some("NANOSIEM_ENCRYPTION_KEY"),
            Self::VectorInstallToken => Some("VECTOR_AUTH_TOKEN"),
            Self::VectorConfigDeliveryToken => Some("NANO_VECTOR_CONFIG_DELIVERY_TOKEN"),
            Self::DbPassword => None,
        }
    }

    /// The kind tag used by `config/known-public-secrets.txt`.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Jwt => "jwt",
            Self::EncryptionKey => "encryption_key",
            Self::VectorInstallToken => "vector_install_token",
            Self::VectorConfigDeliveryToken => "vector_config_delivery_token",
            Self::DbPassword => "db_password",
        }
    }
}

/// Placeholders shipped for every secret kind.
const PLACEHOLDERS: &[&str] = &[
    "CHANGE_ME",
    "CHANGE_ME_GENERATED",
    "CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32",
];

/// `(kind, value)` for every non-placeholder public value nano has shipped.
const SHIPPED: &[(SecretKind, &str)] = &[
    // Dev compose default, `.env.example`, docs and the built-in dev fallback.
    (SecretKind::Jwt, "nanosiem-dev-secret-change-in-production"),
    (SecretKind::Jwt, "your-jwt-secret-change-in-production"),
    (SecretKind::Jwt, "default-dev-jwt-secret-32chars!!"),
    (SecretKind::Jwt, "dev-secret-change-in-production"),
    (SecretKind::Jwt, "dev-secret-not-for-production"),
    (SecretKind::Jwt, "your-secure-secret-here"),
    (SecretKind::Jwt, "your-secure-secret-min-32-chars"),
    (SecretKind::Jwt, "K7xP9qR2sT5uV8wY1zA4bC7dE0fG3hI6jK9lM2nO5pQ8r"),
    (
        SecretKind::Jwt,
        "dev-e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
    ),
    // Encryption: the built-in dev key, old placeholders and the concrete
    // example key `.env.example` shipped until v2.0.1.
    (SecretKind::EncryptionKey, "nanosiem-default-key-32bytes!!"),
    (SecretKind::EncryptionKey, "your-encryption-key-change-in-production"),
    (SecretKind::EncryptionKey, "your_generated_key_here"),
    (
        SecretKind::EncryptionKey,
        "29131984fc00b782da58a3dfed607c3394506e9d11d01264719d91ec2fa8f7fd",
    ),
    // Vector install token: dev compose, the retired deploy CLI, docs.
    (SecretKind::VectorInstallToken, "nanosiem-default-token"),
    (SecretKind::VectorInstallToken, "your-secret-token"),
    // Database passwords: dev compose defaults, .env.example, docs.
    (SecretKind::DbPassword, "nanosiem"),
    (SecretKind::DbPassword, "nanosiem_admin_secret"),
    (SecretKind::DbPassword, "nanosiem_vector_secret"),
    (SecretKind::DbPassword, "nanosiem_ingest"),
    (SecretKind::DbPassword, "your_password"),
    (SecretKind::DbPassword, "postgres"),
];

/// Whether `value` is one of the shared `CHANGE_ME*` placeholders. Nothing
/// real can hold a placeholder (no forwarder was ever given one and nothing was
/// encrypted under one), so tooling may replace them outright.
pub fn is_placeholder(value: &str) -> bool {
    PLACEHOLDERS.contains(&value.trim())
}

/// Whether `value` is a known public value for `kind`. Surrounding whitespace
/// is ignored, as every consumer trims its environment value.
pub fn is_known_public(kind: SecretKind, value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    PLACEHOLDERS.contains(&value)
        || SHIPPED
            .iter()
            .any(|(listed, candidate)| *listed == kind && *candidate == value)
}

/// Every known value for `kind` (placeholders included).
pub fn known_public_values(kind: SecretKind) -> impl Iterator<Item = &'static str> {
    PLACEHOLDERS.iter().copied().chain(
        SHIPPED
            .iter()
            .filter(move |(listed, _)| *listed == kind)
            .map(|(_, value)| *value),
    )
}

/// Whether the environment variable for `kind` currently holds a known public
/// value. Unset and empty count as "not public" (absence is handled by each
/// consumer's own rules).
pub fn env_is_known_public(kind: SecretKind) -> bool {
    let vars: Vec<&str> = match kind.env_var() {
        Some(var) => vec![var],
        None => DB_PASSWORD_ENV_VARS.to_vec(),
    };
    vars.into_iter().any(|var| {
        std::env::var(var)
            .map(|value| is_known_public(kind, &value))
            .unwrap_or(false)
    })
}

/// The shell mirror's line format: `<kind-tag> <value>`.
#[cfg(test)]
fn mirror_lines() -> Vec<String> {
    let kinds = [
        SecretKind::Jwt,
        SecretKind::EncryptionKey,
        SecretKind::VectorInstallToken,
        SecretKind::VectorConfigDeliveryToken,
        SecretKind::DbPassword,
    ];
    let mut lines: Vec<String> = kinds
        .iter()
        .flat_map(|kind| {
            known_public_values(*kind).map(move |value| format!("{} {}", kind.tag(), value))
        })
        .collect();
    lines.sort();
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_values_are_known_per_kind() {
        assert!(is_known_public(
            SecretKind::Jwt,
            "your-jwt-secret-change-in-production"
        ));
        assert!(is_known_public(
            SecretKind::Jwt,
            " nanosiem-dev-secret-change-in-production\n"
        ));
        assert!(is_known_public(
            SecretKind::EncryptionKey,
            "29131984fc00b782da58a3dfed607c3394506e9d11d01264719d91ec2fa8f7fd"
        ));
        assert!(is_known_public(
            SecretKind::VectorInstallToken,
            "nanosiem-default-token"
        ));
        // Kinds do not leak into each other except through shared placeholders.
        assert!(!is_known_public(
            SecretKind::Jwt,
            "nanosiem-default-token"
        ));
        for kind in [
            SecretKind::Jwt,
            SecretKind::EncryptionKey,
            SecretKind::VectorInstallToken,
            SecretKind::VectorConfigDeliveryToken,
        ] {
            assert!(is_known_public(kind, "CHANGE_ME_GENERATED"), "{kind:?}");
        }
    }

    #[test]
    fn generated_and_empty_values_are_not_public() {
        assert!(!is_known_public(SecretKind::Jwt, ""));
        assert!(!is_known_public(SecretKind::Jwt, "   "));
        assert!(!is_known_public(
            SecretKind::Jwt,
            "3f9b1c2d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
        ));
    }

    /// The shell mirror (`config/known-public-secrets.txt`) must list exactly
    /// the same values, or install.sh would keep a value the services refuse.
    /// Read at runtime (not `include_str!`) so a stripped tree still compiles.
    #[test]
    fn shell_mirror_matches_this_list() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../config/known-public-secrets.txt");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let mut mirror: Vec<String> = text
            .lines()
            .map(str::trim_end)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_string)
            .collect();
        mirror.sort();
        assert_eq!(
            mirror,
            mirror_lines(),
            "config/known-public-secrets.txt is out of sync with \
             nanosiem-core/src/known_public_secrets.rs"
        );
    }
}
