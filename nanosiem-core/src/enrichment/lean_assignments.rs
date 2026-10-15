// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live lean enrichment coordinator assignments (NAN-3531).
//!
//! `NANO_LAKE_LEAN_ENRICHMENT_ASSIGNMENTS_FILE` names a server-owned JSON map
//! `{tenant-uuid: {internal_endpoint, credential_file, timeout_secs}}`. It is a
//! directory-mounted ConfigMap, and each `credential_file` lives in a sibling
//! `tokens/` directory that a sidecar keeps current, so tenants are born and
//! offboarded while the process runs.
//!
//! [`LeanAssignmentSource`] re-reads the map at most every
//! [`ASSIGNMENTS_RELOAD_INTERVAL`]:
//! - an unreadable or unparseable FILE keeps the last good map (fail closed
//!   before the first good read);
//! - a malformed ENTRY is dropped alone and does not fail any other tenant;
//! - credential files are NOT read here: every client build reads its own
//!   tenant's token, so a token that appears, rotates, or vanishes is seen on
//!   that tenant's next call, with no map change and no retry bookkeeping.
//!
//! Isolation: an entry is looked up only by the authenticated tenant UUID.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use serde::Deserialize;
use uuid::Uuid;

/// Environment variable naming the mounted assignments file.
pub const LEAN_ENRICHMENT_ASSIGNMENTS_FILE_ENV: &str = "NANO_LAKE_LEAN_ENRICHMENT_ASSIGNMENTS_FILE";
/// How often the assignments file is re-read.
pub const ASSIGNMENTS_RELOAD_INTERVAL: Duration = Duration::from_secs(10);
/// Size bound of the assignments file.
pub const MAX_ASSIGNMENT_BYTES: usize = 1024 * 1024;
/// Tenant bound of the assignments file.
pub const MAX_ASSIGNMENTS: usize = 1_024;

/// One tenant's coordinator assignment, admitted by [`LeanAssignments::parse`]:
/// a non-nil tenant key, no unknown fields, `timeout_secs` in `1..=3600`, and an
/// absolute `credential_file`. Origin and credential checks belong to the
/// client that uses it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeanCoordinatorAssignment {
    pub internal_endpoint: String,
    pub credential_file: PathBuf,
    pub timeout_secs: u64,
}

/// One parsed assignments file.
#[derive(Debug, Default, PartialEq)]
pub struct LeanAssignments {
    entries: HashMap<Uuid, LeanCoordinatorAssignment>,
    /// Tenants whose entry was dropped: their lookups fail closed instead of
    /// reading as "not assigned".
    rejected: HashSet<Uuid>,
}

/// What [`LeanAssignments::get`] found for one tenant.
#[derive(Debug, PartialEq)]
pub enum LeanAssignmentLookup<'a> {
    Assigned(&'a LeanCoordinatorAssignment),
    NotAssigned,
    /// The tenant's entry is present but malformed.
    Invalid,
}

impl LeanAssignments {
    /// Parse one file. A file-level fault (not a JSON object, a duplicate
    /// key, over [`MAX_ASSIGNMENTS`]) is an error; a malformed entry is
    /// dropped alone and reported in the second value.
    pub fn parse(bytes: &[u8]) -> Result<(Self, Vec<String>), String> {
        let UniqueKeyObject(object) = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid lean coordinator assignments: {error}"))?;
        let mut parsed = Self::default();
        let mut dropped = Vec::new();
        for (key, value) in object {
            let tenant = match Uuid::parse_str(&key) {
                Ok(tenant) if !tenant.is_nil() => tenant,
                _ => {
                    dropped.push(format!("tenant key {key:?} is not a non-nil UUID"));
                    continue;
                }
            };
            match serde_json::from_value::<LeanCoordinatorAssignment>(value) {
                Ok(entry)
                    if (1..=3_600).contains(&entry.timeout_secs)
                        && entry.credential_file.is_absolute() =>
                {
                    parsed.entries.insert(tenant, entry);
                }
                Ok(_) => {
                    parsed.rejected.insert(tenant);
                    dropped.push(format!(
                        "tenant {tenant}: timeout_secs must be 1..=3600 and credential_file absolute"
                    ));
                }
                Err(error) => {
                    parsed.rejected.insert(tenant);
                    dropped.push(format!("tenant {tenant}: {error}"));
                }
            }
        }
        Ok((parsed, dropped))
    }

    /// Read and parse a file once, with no last-good fallback.
    pub fn read_file(path: &Path) -> Result<(Self, Vec<String>), String> {
        let bytes = read_regular_file(path, MAX_ASSIGNMENT_BYTES)
            .map_err(|error| format!("cannot read lean coordinator assignments: {error}"))?;
        Self::parse(&bytes)
    }

    /// The entry of exactly this tenant.
    pub fn get(&self, tenant_id: Uuid) -> LeanAssignmentLookup<'_> {
        if tenant_id.is_nil() || self.rejected.contains(&tenant_id) {
            return LeanAssignmentLookup::Invalid;
        }
        match self.entries.get(&tenant_id) {
            Some(entry) => LeanAssignmentLookup::Assigned(entry),
            None => LeanAssignmentLookup::NotAssigned,
        }
    }

    /// Every OTHER tenant's admitted entry, for the caller's aliasing check.
    pub fn others(&self, tenant_id: Uuid) -> impl Iterator<Item = &LeanCoordinatorAssignment> {
        self.entries
            .iter()
            .filter(move |(other, _)| **other != tenant_id)
            .map(|(_, entry)| entry)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// What the last read saw.
#[derive(Default)]
struct ReloadState {
    at: Option<Instant>,
    /// The bytes of the last read, good or bad (so a bad file logs once).
    bytes: Option<Vec<u8>>,
}

/// The live-reloaded assignments file.
pub struct LeanAssignmentSource {
    path: PathBuf,
    interval: Duration,
    /// `None` until the first good read: lookups fail closed until then.
    current: RwLock<Option<Arc<LeanAssignments>>>,
    last: Mutex<ReloadState>,
}

impl LeanAssignmentSource {
    /// A source over `path`, read now and then every
    /// [`ASSIGNMENTS_RELOAD_INTERVAL`].
    pub fn new(path: &Path) -> Self {
        Self::with_interval(path, ASSIGNMENTS_RELOAD_INTERVAL)
    }

    /// [`Self::new`] with an explicit re-read interval (tests).
    pub fn with_interval(path: &Path, interval: Duration) -> Self {
        let source = Self {
            path: path.to_path_buf(),
            interval,
            current: RwLock::new(None),
            last: Mutex::new(ReloadState::default()),
        };
        source.reload();
        source
    }

    /// The process-wide source of `path`: every reader of the same file in
    /// this process shares one cache.
    pub fn shared(path: &Path) -> Arc<Self> {
        static SOURCES: OnceLock<Mutex<HashMap<PathBuf, Arc<LeanAssignmentSource>>>> =
            OnceLock::new();
        let sources = SOURCES.get_or_init(|| Mutex::new(HashMap::new()));
        let mut sources = sources
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(
            sources
                .entry(path.to_path_buf())
                .or_insert_with(|| Arc::new(Self::new(path))),
        )
    }

    /// The shared source named by [`LEAN_ENRICHMENT_ASSIGNMENTS_FILE_ENV`], or
    /// `None` when it is unset.
    pub fn from_env() -> Option<Arc<Self>> {
        std::env::var_os(LEAN_ENRICHMENT_ASSIGNMENTS_FILE_ENV)
            .map(PathBuf::from)
            .map(|path| Self::shared(&path))
    }

    /// The current map, re-reading the file when it is due. `Err` only until
    /// the first good read.
    pub fn current(&self) -> Result<Arc<LeanAssignments>, String> {
        let due = self
            .last
            .lock()
            .map(|last| last.at.is_none_or(|at| at.elapsed() >= self.interval))
            .unwrap_or(false);
        if due {
            self.reload();
        }
        self.current
            .read()
            .ok()
            .and_then(|current| current.as_ref().map(Arc::clone))
            .ok_or_else(|| "lean coordinator assignments are not loaded".to_string())
    }

    /// Re-read the file now. Keeps the previous map on any file-level error.
    pub fn reload(&self) {
        let Ok(mut last) = self.last.lock() else {
            return;
        };
        last.at = Some(Instant::now());
        let bytes = match read_regular_file(&self.path, MAX_ASSIGNMENT_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => {
                if last.bytes.take().is_some() {
                    tracing::error!(path = %self.path.display(), %error, "lean coordinator assignments unreadable; keeping the previous map");
                }
                return;
            }
        };
        if last.bytes.as_deref() == Some(bytes.as_slice()) {
            return;
        }
        match LeanAssignments::parse(&bytes) {
            Ok((assignments, dropped)) => {
                for reason in &dropped {
                    tracing::error!(reason = %reason, "lean coordinator assignment dropped");
                }
                tracing::info!(
                    tenants = assignments.len(),
                    dropped = dropped.len(),
                    "lean coordinator assignments loaded"
                );
                if let Ok(mut current) = self.current.write() {
                    *current = Some(Arc::new(assignments));
                }
            }
            Err(error) => {
                tracing::error!(path = %self.path.display(), %error, "lean coordinator assignments invalid; keeping the previous map");
            }
        }
        last.bytes = Some(bytes);
    }
}

/// A JSON object whose keys are unique, bounded by [`MAX_ASSIGNMENTS`].
struct UniqueKeyObject(Vec<(String, serde_json::Value)>);

impl<'de> Deserialize<'de> for UniqueKeyObject {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueKeyObject;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a JSON object with unique tenant keys")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut seen = HashSet::new();
                let mut entries = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    if entries.len() >= MAX_ASSIGNMENTS {
                        return Err(serde::de::Error::custom(
                            "assignments exceed their tenant bound",
                        ));
                    }
                    if !seen.insert(key.clone()) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate tenant key {key:?}"
                        )));
                    }
                    entries.push((key, value));
                }
                Ok(UniqueKeyObject(entries))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

/// Follow mounted-secret symlinks, then refuse special files before opening.
/// O_NONBLOCK prevents a FIFO swapped in between metadata and open from hanging;
/// O_NOFOLLOW refuses a final-component symlink swap. Check the opened fd too.
pub(crate) fn read_regular_file(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    let invalid = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid configuration file",
        )
    };
    let canonical = std::fs::canonicalize(path)?;
    if !std::fs::metadata(&canonical)?.is_file() {
        return Err(invalid());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options.open(canonical)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(port: u16, credential: &Path) -> serde_json::Value {
        serde_json::json!({"internal_endpoint": format!("http://127.0.0.1:{port}"), "credential_file": credential, "timeout_secs": 30})
    }

    fn write(path: &Path, value: &serde_json::Value) {
        std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    }

    #[test]
    fn a_malformed_entry_is_dropped_alone_and_fails_only_its_tenant() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut bad = entry(10, Path::new("/t/b"));
        bad["unexpected"] = serde_json::json!(true);
        let bytes = serde_json::to_vec(&serde_json::json!({
            a.to_string(): entry(9, Path::new("/t/a")),
            b.to_string(): bad,
            "not-a-uuid": entry(11, Path::new("/t/c")),
            Uuid::nil().to_string(): entry(12, Path::new("/t/d")),
        }))
        .unwrap();
        let (parsed, dropped) = LeanAssignments::parse(&bytes).unwrap();
        assert_eq!(dropped.len(), 3);
        assert!(matches!(parsed.get(a), LeanAssignmentLookup::Assigned(_)));
        assert_eq!(parsed.get(b), LeanAssignmentLookup::Invalid);
        assert_eq!(
            parsed.get(Uuid::new_v4()),
            LeanAssignmentLookup::NotAssigned
        );
        assert_eq!(parsed.get(Uuid::nil()), LeanAssignmentLookup::Invalid);
        assert_eq!(
            parsed.others(a).count(),
            0,
            "dropped entries are not served"
        );
    }

    #[test]
    fn file_level_faults_are_errors() {
        for bytes in [b"not JSON".as_slice(), b"[]", b"{\"a\":1,\"a\":2}"] {
            assert!(LeanAssignments::parse(bytes).is_err());
        }
        let mut map = serde_json::Map::new();
        for _ in 0..=MAX_ASSIGNMENTS {
            map.insert(Uuid::new_v4().to_string(), entry(9, Path::new("/t")));
        }
        assert!(LeanAssignments::parse(&serde_json::to_vec(&map).unwrap()).is_err());
    }

    /// The map reloads on its interval, keeps the last good map on a bad
    /// file, and fails closed before its first good read.
    #[test]
    fn the_source_reloads_and_keeps_the_last_good_map() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("assignments.json");
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let source = LeanAssignmentSource::with_interval(&file, Duration::ZERO);
        assert!(source.current().is_err(), "no file yet: fail closed");

        write(
            &file,
            &serde_json::json!({ a.to_string(): entry(9, &dir.path().join("a")) }),
        );
        assert!(matches!(
            source.current().unwrap().get(a),
            LeanAssignmentLookup::Assigned(_)
        ));

        std::fs::write(&file, b"{ torn").unwrap();
        assert!(
            matches!(
                source.current().unwrap().get(a),
                LeanAssignmentLookup::Assigned(_)
            ),
            "a bad file keeps the last good map"
        );
        std::fs::remove_file(&file).unwrap();
        assert!(matches!(
            source.current().unwrap().get(a),
            LeanAssignmentLookup::Assigned(_)
        ));

        write(
            &file,
            &serde_json::json!({
                a.to_string(): entry(9, &dir.path().join("a")),
                b.to_string(): entry(10, &dir.path().join("b")),
            }),
        );
        assert!(matches!(
            source.current().unwrap().get(b),
            LeanAssignmentLookup::Assigned(_)
        ));
    }

    /// The default interval holds a read until it is due; `reload` forces it.
    #[test]
    fn the_interval_holds_until_a_forced_reload() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("assignments.json");
        let a = Uuid::new_v4();
        write(&file, &serde_json::json!({}));
        let source = LeanAssignmentSource::new(&file);
        write(
            &file,
            &serde_json::json!({ a.to_string(): entry(9, &dir.path().join("a")) }),
        );
        assert_eq!(
            source.current().unwrap().get(a),
            LeanAssignmentLookup::NotAssigned
        );
        source.reload();
        assert!(matches!(
            source.current().unwrap().get(a),
            LeanAssignmentLookup::Assigned(_)
        ));
    }
}
