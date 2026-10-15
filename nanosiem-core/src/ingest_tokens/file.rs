// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vector's hashed tokens file (nano-rs/vector `valid_tokens_file`).
//!
//! Format (version 1): `{"version":1,"fallback_enabled":bool,"tokens":[{"sha256","id","name"}]}`.
//! `fallback_enabled` = whether the sources' static install token (HEC
//! `valid_tokens`, the HTTP `auth` VRL) is still consulted for a token that is
//! not listed. The file holds hashes only; it is still written 0600 and its
//! content is never logged.
//!
//! NAN-3806: an entry's `name` is what the fork stamps as
//! `%nano_credential_name`, and nano renders the bound source's route key
//! there: the HEC / HTTP lanes set `.source_type` from it. The display name
//! of a token stays in PostgreSQL. [`PLATFORM_PULL_ROUTE`] marks the platform
//! pull credential, whose events keep the source type they declare.

use std::io::Write as _;
use std::path::Path;

use serde::Serialize;
use uuid::Uuid;

/// Where nano-api writes the file. Vector reads the same path through the
/// shared `nano-vector-dynamic` volume (`/etc/vector/dynamic`).
pub const DEFAULT_TOKENS_FILE: &str = "/etc/vector/dynamic/ingest-tokens/tokens.json";

/// Route of the platform pull credential's entry. Never a route key: a log
/// source's route key is a match value or a safe name, neither of which can
/// be `*` (the lanes key on the credential id anyway).
pub const PLATFORM_PULL_ROUTE: &str = "*";

/// One accepted token in the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TokenFileEntry {
    pub sha256: String,
    pub id: Uuid,
    /// The bound source's route key (stamped as `%nano_credential_name`).
    #[serde(rename = "name")]
    pub route: String,
}

#[derive(Serialize)]
struct TokensFile<'a> {
    version: u32,
    fallback_enabled: bool,
    tokens: &'a [TokenFileEntry],
}

/// Renders the file. Entries are sorted by id so equal state renders equal
/// bytes (an unchanged file is not rewritten, and Vector does not reload).
pub fn render_tokens_file(entries: &[TokenFileEntry], fallback_enabled: bool) -> String {
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|entry| entry.id);
    let mut out = serde_json::to_string_pretty(&TokensFile {
        version: 1,
        fallback_enabled,
        tokens: &sorted,
    })
    .expect("tokens file serializes");
    out.push('\n');
    out
}

/// Atomically replaces `path` with `content` (0600 temp file in the same
/// directory, fsync, rename). Returns `false` when the file already had that
/// content and was left alone.
pub fn write_tokens_file(path: &Path, content: &str) -> std::io::Result<bool> {
    if std::fs::read(path).is_ok_and(|current| current == content.as_bytes()) {
        return Ok(false);
    }
    let dir = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tokens file has no parent directory",
        )
    })?;
    std::fs::create_dir_all(dir)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".tokens-")
        .suffix(".tmp")
        .permissions(restricted_permissions())
        .tempfile_in(dir)?;
    tmp.write_all(content.as_bytes())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|error| error.error)?;
    if let Ok(dir) = std::fs::File::open(dir) {
        let _ = dir.sync_all();
    }
    Ok(true)
}

#[cfg(unix)]
fn restricted_permissions() -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::Permissions::from_mode(0o600)
}

#[cfg(not(unix))]
fn restricted_permissions() -> std::fs::Permissions {
    std::fs::metadata(".").expect("cwd").permissions()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: u128, name: &str) -> TokenFileEntry {
        TokenFileEntry {
            sha256: format!("{n:064x}"),
            id: Uuid::from_u128(n),
            route: name.into(),
        }
    }

    #[test]
    fn renders_the_fork_format_sorted() {
        let text = render_tokens_file(&[entry(2, "b"), entry(1, "a")], true);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["fallback_enabled"], true);
        let tokens = value["tokens"].as_array().unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0]["id"], Uuid::from_u128(1).to_string());
        assert_eq!(tokens[0]["sha256"], format!("{:064x}", 1));
        assert_eq!(tokens[0]["name"], "a");
        assert_eq!(
            text,
            render_tokens_file(&[entry(1, "a"), entry(2, "b")], true),
            "order-independent"
        );
        let disabled: serde_json::Value =
            serde_json::from_str(&render_tokens_file(&[], false)).unwrap();
        assert_eq!(disabled["fallback_enabled"], false);
        assert_eq!(disabled["tokens"], serde_json::json!([]));
    }

    #[test]
    fn writes_atomically_with_0600_and_skips_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ingest-tokens/tokens.json");
        let content = render_tokens_file(&[entry(1, "a")], true);
        assert!(write_tokens_file(&path, &content).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(!write_tokens_file(&path, &content).unwrap(), "unchanged");
        let next = render_tokens_file(&[], true);
        assert!(write_tokens_file(&path, &next).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), next);
        // No temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }
}
