// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lean-lake OTLP drain routes (NAN-3243).
//!
//! A lean-lake tenant is not in the gen1 worker registry, so its
//! `lake_otel_ingest` (lean mode: handoff -> local mirror, see
//! `nanosiem_lake_worker::otel_lean`) cannot ride the registry's
//! `otel_ingest` block. The platform publishes one more server-owned input into
//! the search namespace instead:
//!
//! * a ConfigMap key mounted as a DIRECTORY (atomic `..data` swap), named by
//!   `NANO_LEAN_OTEL_ROUTES_FILE`: a flat JSON object mapping each tenant
//!   UUID that has a lean OTLP drain to
//!   `{"internal_endpoint": "http://<svc>:<port>", "credential_file": "<abs path>", "timeout_secs": 130}`
//!   (`timeout_secs` optional). The credential file is that drain's QUERY
//!   token, mounted from a Secret.
//!
//! Admission is the registry's for `otel_ingest`: a private-network or
//! cluster-DNS HTTP(S) origin with an explicit port, an absolute private
//! credential file, both unique across tenants, timeout 1..=3600.
//!
//! Failure isolation (as for cell routes): nothing here may fail the
//! process's boot. Without the variable no tenant has a lean OTLP route; a
//! malformed ENTRY is dropped alone (logged); an unreadable or unparseable
//! FILE keeps the last good map (empty at boot). The file is re-read at most
//! every [`ROUTES_RELOAD_INTERVAL`], so enabling OTLP for a tenant needs no
//! search restart. A credential file that appears, rotates, or vanishes is
//! picked up on the next reload even when the routes file is unchanged
//! (NAN-3531).
//!
//! Isolation: a route is looked up only by the authenticated tenant UUID.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use uuid::Uuid;

use super::lake::{admit_private_credential_file, validate_internal_worker_endpoint};
use super::SharedLakeOtelIngestAssignment;

/// Environment variable naming the mounted lean OTLP routes file.
pub const LEAN_OTEL_ROUTES_FILE_ENV: &str = "NANO_LEAN_OTEL_ROUTES_FILE";
/// How often the routes file is re-read.
pub const ROUTES_RELOAD_INTERVAL: Duration = Duration::from_secs(10);
const DEFAULT_TIMEOUT_SECS: u64 = 130;
const MAX_ROUTES: usize = 4_096;
const MAX_ROUTES_FILE_BYTES: u64 = 1024 * 1024;

/// A JSON object whose keys are unique, in document order.
struct UniqueKeyObject(Vec<(String, serde_json::Value)>);

impl<'de> serde::Deserialize<'de> for UniqueKeyObject {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueKeyObject;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a JSON object with unique tenant keys")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut seen = HashSet::new();
                let mut entries = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    if entries.len() >= MAX_ROUTES {
                        return Err(serde::de::Error::custom("lean OTLP routes map exceeds its tenant bound"));
                    }
                    if !seen.insert(key.clone()) {
                        return Err(serde::de::Error::custom(format!("duplicate tenant key {key:?}")));
                    }
                    entries.push((key, value));
                }
                Ok(UniqueKeyObject(entries))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

/// The identity of a credential file: `(dev, ino, len, mtime)` of the file
/// its path resolves to (mounted-secret symlinks followed), or `None` when it
/// is absent or unreadable. The materializer replaces a token by an atomic
/// rename, so a rotation always changes the inode.
type CredentialIdentity = Option<(u64, u64, u64, Option<std::time::SystemTime>)>;

fn credential_identity(path: &Path) -> CredentialIdentity {
    let metadata = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    let (dev, ino) = {
        use std::os::unix::fs::MetadataExt;
        (metadata.dev(), metadata.ino())
    };
    #[cfg(not(unix))]
    let (dev, ino) = (0, 0);
    Some((dev, ino, metadata.len(), metadata.modified().ok()))
}

/// The identities of every credential file one routes file names.
#[derive(Debug, Default, PartialEq)]
struct CredentialSnapshot(Vec<(PathBuf, CredentialIdentity)>);

impl CredentialSnapshot {
    fn take(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        Self(
            paths
                .into_iter()
                .map(|path| {
                    let identity = credential_identity(&path);
                    (path, identity)
                })
                .collect(),
        )
    }

    /// Whether any file's identity differs from the snapshot now.
    fn changed(&self) -> bool {
        self.0
            .iter()
            .any(|(path, identity)| credential_identity(path) != *identity)
    }
}

/// One parsed routes file.
#[derive(Debug, Default, PartialEq)]
pub struct LeanOtelRoutes {
    routes: HashMap<Uuid, SharedLakeOtelIngestAssignment>,
    generation: u64,
}

impl LeanOtelRoutes {
    /// Changes whenever routes or credential identities are republished.
    pub fn generation(&self) -> u64 { self.generation }

    /// Parse the routes file. A structurally invalid file is an error (the
    /// caller keeps its previous map); a malformed ENTRY is dropped alone and
    /// reported in the second value.
    pub fn parse(bytes: &[u8]) -> Result<(Self, Vec<String>), String> {
        Self::parse_watched(bytes).map(|(routes, rejected, _)| (routes, rejected))
    }

    /// [`Self::parse`], plus the identity of every entry's credential file
    /// (admitted or dropped), snapshotted BEFORE any entry is admitted: a
    /// file that changes after the snapshot is seen as changed on the next
    /// reload, never missed (NAN-3531).
    fn parse_watched(bytes: &[u8]) -> Result<(Self, Vec<String>, CredentialSnapshot), String> {
        // NAN-3286: a duplicate tenant key makes the file ambiguous (serde's
        // map would silently keep the last one); refuse the whole file.
        let UniqueKeyObject(object) = serde_json::from_slice(bytes)
            .map_err(|error| format!("lean OTLP routes file is not a JSON object: {error}"))?;
        if object.len() > MAX_ROUTES {
            return Err("lean OTLP routes map exceeds its tenant bound".to_string());
        }
        let watched = CredentialSnapshot::take(object.iter().filter_map(|(_, value)| {
            value
                .get("credential_file")
                .and_then(serde_json::Value::as_str)
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
        }));
        let mut rejected = Vec::new();
        let mut routes = HashMap::with_capacity(object.len());
        let mut endpoints = HashSet::new();
        let mut credentials = HashSet::new();
        let mut entries = object;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (key, value) in entries {
            match Self::entry(&key, &value) {
                Ok((tenant, assignment)) => {
                    // Dedup on the parsed origin, so `HTTP://Drain.svc:1`
                    // and `http://drain.svc:1/` are one endpoint (NAN-3286).
                    let origin = url::Url::parse(&assignment.internal_endpoint)
                        .map(|url| url.origin().ascii_serialization())
                        .unwrap_or_else(|_| assignment.internal_endpoint.clone());
                    if !endpoints.insert(origin) {
                        rejected.push(format!(
                            "route for {tenant} reuses another tenant's endpoint"
                        ));
                        continue;
                    }
                    if !credentials.insert(assignment.credential_file.clone()) {
                        rejected.push(format!(
                            "route for {tenant} reuses another tenant's credential file"
                        ));
                        continue;
                    }
                    routes.insert(tenant, assignment);
                }
                Err(error) => rejected.push(error),
            }
        }
        Ok((Self { routes, generation: 0 }, rejected, watched))
    }

    fn entry(
        key: &str,
        value: &serde_json::Value,
    ) -> Result<(Uuid, SharedLakeOtelIngestAssignment), String> {
        let tenant = Uuid::parse_str(key)
            .ok()
            .filter(|tenant| !tenant.is_nil() && tenant.as_hyphenated().to_string() == key)
            .ok_or_else(|| format!("key {key:?} is not a lowercase hyphenated tenant UUID"))?;
        let object = value
            .as_object()
            .ok_or_else(|| format!("route for {tenant} is not an object"))?;
        if object.keys().any(|field| {
            !matches!(
                field.as_str(),
                "internal_endpoint" | "credential_file" | "timeout_secs"
            )
        }) {
            return Err(format!("route for {tenant} has unexpected fields"));
        }
        let endpoint = object
            .get("internal_endpoint")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("route for {tenant} has no internal_endpoint"))?;
        validate_internal_worker_endpoint(endpoint)
            .map_err(|error| format!("route for {tenant}: {error}"))?;
        let credential = object
            .get("credential_file")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("route for {tenant} has no credential_file"))?;
        let credential_file =
            admit_private_credential_file(Path::new(credential), &tenant, "lean OTLP drain")?;
        let timeout_secs = match object.get("timeout_secs") {
            None => DEFAULT_TIMEOUT_SECS,
            Some(value) => value
                .as_u64()
                .filter(|secs| (1..=3_600).contains(secs))
                .ok_or_else(|| {
                    format!("route for {tenant} timeout must be between 1 and 3600 seconds")
                })?,
        };
        Ok((
            tenant,
            SharedLakeOtelIngestAssignment {
                internal_endpoint: endpoint.to_string(),
                credential_file,
                timeout_secs,
            },
        ))
    }

    /// The route of exactly this authenticated tenant, or `None`.
    pub fn route(&self, tenant_id: Uuid) -> Option<&SharedLakeOtelIngestAssignment> {
        self.routes.get(&tenant_id)
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// What the last successful parse saw.
#[derive(Default)]
struct ReloadState {
    /// When the file was last read.
    at: Option<Instant>,
    /// Its bytes at the last successful parse.
    bytes: Vec<u8>,
    /// Why entries were dropped at the last successful parse.
    rejected: Vec<String>,
    /// Every named credential file's identity at the last successful parse.
    credentials: CredentialSnapshot,
}

/// The live-reloaded routes file.
///
/// NAN-3531: tenant credential files appear in, rotate in, and vanish from an
/// already-mounted directory while the process runs, so a reload re-parses
/// not only when the routes bytes change but also when the last parse dropped
/// an entry (its token may have appeared or become private) or when any named
/// credential file's identity changed. A re-parse that changes the map or any
/// credential identity publishes a NEW map `Arc`, which is what makes
/// nanosiem-search's `LeanOtelClients` drop its cached clients and re-read a
/// rotated token within one reload.
pub struct LeanOtelRouteSource {
    path: PathBuf,
    current: RwLock<Arc<LeanOtelRoutes>>,
    last: Mutex<ReloadState>,
}

impl LeanOtelRouteSource {
    /// `None` when [`LEAN_OTEL_ROUTES_FILE_ENV`] is unset or empty.
    pub fn from_env() -> Option<Arc<Self>> {
        let path = std::env::var(LEAN_OTEL_ROUTES_FILE_ENV).ok()?;
        let path = path.trim();
        if path.is_empty() {
            return None;
        }
        Some(Arc::new(Self::from_file(Path::new(path))))
    }

    pub fn from_file(path: &Path) -> Self {
        let source = Self {
            path: path.to_path_buf(),
            current: RwLock::new(Arc::new(LeanOtelRoutes::default())),
            last: Mutex::new(ReloadState::default()),
        };
        source.reload();
        source
    }

    /// The current map, re-reading the file when it is due.
    pub fn current(&self) -> Arc<LeanOtelRoutes> {
        let due = self
            .last
            .lock()
            .map(|last| {
                last.at
                    .is_none_or(|at| at.elapsed() >= ROUTES_RELOAD_INTERVAL)
            })
            .unwrap_or(false);
        if due {
            self.reload();
        }
        self.current
            .read()
            .map(|routes| Arc::clone(&routes))
            .unwrap_or_default()
    }

    /// Re-read the file now. Keeps the previous map on any file-level error.
    pub fn reload(&self) {
        let Ok(mut last) = self.last.lock() else {
            return;
        };
        last.at = Some(Instant::now());
        let bytes = match read_bounded(&self.path) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::error!(path = %self.path.display(), %error, "lean OTLP routes file unreadable; keeping the previous map");
                return;
            }
        };
        let bytes_changed = bytes != last.bytes;
        if !bytes_changed && last.rejected.is_empty() && !last.credentials.changed() {
            return;
        }
        match LeanOtelRoutes::parse_watched(&bytes) {
            Ok((mut routes, rejected, credentials)) => {
                let credentials_changed = credentials != last.credentials;
                let map_changed = self
                    .current
                    .read()
                    .map(|current| current.routes != routes.routes)
                    .unwrap_or(true);
                let publish = map_changed || credentials_changed;
                if publish || bytes_changed || rejected != last.rejected {
                    for reason in &rejected {
                        tracing::error!(reason = %reason, "lean OTLP route dropped");
                    }
                    tracing::info!(
                        tenants = routes.len(),
                        dropped = rejected.len(),
                        credentials_changed,
                        "lean OTLP routes loaded"
                    );
                }
                if publish {
                    if let Ok(mut current) = self.current.write() {
                        routes.generation = current.generation.saturating_add(1);
                        *current = Arc::new(routes);
                    }
                }
                last.bytes = bytes;
                last.rejected = rejected;
                last.credentials = credentials;
            }
            Err(error) => {
                // Logged once per bad file version, not every interval.
                if bytes_changed {
                    tracing::error!(path = %self.path.display(), %error, "lean OTLP routes file invalid; keeping the previous map");
                }
                last.bytes = bytes;
            }
        }
    }
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = std::fs::metadata(path).map_err(|error| error.to_string())?;
    if metadata.len() > MAX_ROUTES_FILE_BYTES {
        return Err("lean OTLP routes file exceeds its size bound".to_string());
    }
    std::fs::read(path).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, "t".repeat(48)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        path
    }

    #[test]
    fn routes_admit_good_entries_and_drop_bad_ones_alone() {
        let dir = tempfile::tempdir().unwrap();
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let c = Uuid::now_v7();
        let ta = token(dir.path(), "a");
        let tb = token(dir.path(), "b");
        let json = serde_json::json!({
            a.to_string(): {"internal_endpoint": "http://nano-lean-otel-a.nano-lean.svc:3014", "credential_file": ta},
            b.to_string(): {"internal_endpoint": "http://nano-lean-otel-a.nano-lean.svc:3014", "credential_file": tb},
            c.to_string(): {"internal_endpoint": "https://example.com:443", "credential_file": tb},
            "NOT-A-UUID": {"internal_endpoint": "http://x.svc:1", "credential_file": tb},
        });
        let (routes, rejected) =
            LeanOtelRoutes::parse(serde_json::to_vec(&json).unwrap().as_slice()).unwrap();
        assert_eq!(routes.len(), 1);
        let route = routes.route(a).or_else(|| routes.route(b)).unwrap();
        assert_eq!(route.timeout_secs, DEFAULT_TIMEOUT_SECS);
        assert_eq!(rejected.len(), 3, "{rejected:?}");
        assert!(routes.route(c).is_none(), "a public endpoint is refused");
    }

    /// NAN-3286: a duplicate tenant key refuses the whole file (the source
    /// keeps its last good map), and endpoints dedup on the parsed origin.
    #[test]
    fn duplicate_tenant_keys_and_respelled_endpoints_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let a = Uuid::now_v7();
        let ta = token(dir.path(), "a");
        let tb = token(dir.path(), "b");
        let ta = ta.display();
        let tb = tb.display();
        let duplicate = format!(
            r#"{{"{a}": {{"internal_endpoint": "http://nano-lean-otel-a.nano-lean.svc:3014", "credential_file": "{ta}"}},
                "{a}": {{"internal_endpoint": "http://nano-lean-otel-b.nano-lean.svc:3014", "credential_file": "{tb}"}}}}"#
        );
        let error = LeanOtelRoutes::parse(duplicate.as_bytes()).unwrap_err();
        assert!(error.contains("duplicate tenant key"), "{error}");

        let b = Uuid::now_v7();
        let respelled = format!(
            r#"{{"{a}": {{"internal_endpoint": "http://nano-lean-otel-a.nano-lean.svc:3014", "credential_file": "{ta}"}},
                "{b}": {{"internal_endpoint": "HTTP://NANO-LEAN-OTEL-A.nano-lean.svc:3014/", "credential_file": "{tb}"}}}}"#
        );
        let (routes, rejected) = LeanOtelRoutes::parse(respelled.as_bytes()).unwrap();
        assert_eq!(routes.len(), 1, "{rejected:?}");
        assert!(rejected.iter().any(|reason| reason.contains("endpoint")), "{rejected:?}");
    }

    #[test]
    fn unexpected_fields_and_bad_timeouts_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::now_v7();
        let file = token(dir.path(), "t");
        for value in [
            serde_json::json!({"internal_endpoint": "http://o.svc:3014", "credential_file": file, "extra": 1}),
            serde_json::json!({"internal_endpoint": "http://o.svc:3014", "credential_file": file, "timeout_secs": 0}),
            serde_json::json!({"internal_endpoint": "http://o.svc", "credential_file": file}),
            serde_json::json!({"internal_endpoint": "http://o.svc:3014", "credential_file": "relative"}),
        ] {
            let json = serde_json::json!({ tenant.to_string(): value });
            let (routes, rejected) =
                LeanOtelRoutes::parse(&serde_json::to_vec(&json).unwrap()).unwrap();
            assert!(routes.is_empty() && rejected.len() == 1, "{value}");
        }
    }

    #[test]
    fn a_public_credential_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("open");
        std::fs::write(&path, "t".repeat(48)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let tenant = Uuid::now_v7();
            let json = serde_json::json!({ tenant.to_string(): {"internal_endpoint": "http://o.svc:3014", "credential_file": path} });
            let (routes, _) = LeanOtelRoutes::parse(&serde_json::to_vec(&json).unwrap()).unwrap();
            assert!(routes.is_empty());
        }
    }

    #[test]
    fn source_keeps_the_last_good_map_on_a_broken_file_and_picks_up_changes() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::now_v7();
        let file = token(dir.path(), "t");
        let routes_path = dir.path().join("routes.json");
        let good = serde_json::json!({ tenant.to_string(): {"internal_endpoint": "http://o.svc:3014", "credential_file": file} });
        std::fs::write(&routes_path, serde_json::to_vec(&good).unwrap()).unwrap();
        let source = LeanOtelRouteSource::from_file(&routes_path);
        assert!(source.current().route(tenant).is_some());
        std::fs::write(&routes_path, b"{broken").unwrap();
        source.reload();
        assert!(
            source.current().route(tenant).is_some(),
            "a broken file keeps the last good map"
        );
        std::fs::write(&routes_path, b"{}").unwrap();
        source.reload();
        assert!(
            source.current().route(tenant).is_none(),
            "a removed route is dropped"
        );
        let missing = LeanOtelRouteSource::from_file(&dir.path().join("absent.json"));
        assert!(
            missing.current().is_empty(),
            "a missing file is an empty map, not a boot failure"
        );
    }

    /// Atomically replace a token, as the credential materializer does.
    fn rotate(dir: &Path, name: &str, content: &str) {
        let staging = dir.join(format!(".{name}.tmp"));
        std::fs::write(&staging, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        std::fs::rename(&staging, dir.join(name)).unwrap();
    }

    fn write_routes(path: &Path, routes: &serde_json::Value) {
        std::fs::write(path, serde_json::to_vec(routes).unwrap()).unwrap();
    }

    /// NAN-3531: a tenant's token lands in the mounted directory after its
    /// route; the next reload admits it with routes.json unchanged.
    #[test]
    fn a_token_that_appears_later_is_admitted_without_a_routes_change() {
        let dir = tempfile::tempdir().unwrap();
        let tokens = dir.path().join("tokens");
        std::fs::create_dir(&tokens).unwrap();
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let ta = token(&tokens, &a.to_string());
        let routes_path = dir.path().join("routes.json");
        write_routes(
            &routes_path,
            &serde_json::json!({
                a.to_string(): {"internal_endpoint": "http://otel-a.svc:3014", "credential_file": ta},
                b.to_string(): {"internal_endpoint": "http://otel-b.svc:3014", "credential_file": tokens.join(b.to_string())},
            }),
        );
        let routes_bytes = std::fs::read(&routes_path).unwrap();
        let source = LeanOtelRouteSource::from_file(&routes_path);
        assert!(source.current().route(a).is_some());
        assert!(source.current().route(b).is_none(), "no token yet");

        // A reload with nothing changed keeps the very same map.
        let before = source.current();
        source.reload();
        assert!(Arc::ptr_eq(&before, &source.current()));

        rotate(&tokens, &b.to_string(), &"b".repeat(48));
        source.reload();
        assert_eq!(std::fs::read(&routes_path).unwrap(), routes_bytes);
        let routes = source.current();
        assert!(routes.route(b).is_some(), "token appeared: admitted");
        assert!(routes.route(a).is_some());
        assert_ne!(
            routes.route(a).unwrap().credential_file,
            routes.route(b).unwrap().credential_file,
            "each tenant keeps its own credential"
        );
    }

    /// NAN-3531: a token removed from the directory drops only that route.
    #[test]
    fn a_removed_token_drops_its_route_alone() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let ta = token(dir.path(), "a");
        let tb = token(dir.path(), "b");
        let routes_path = dir.path().join("routes.json");
        write_routes(
            &routes_path,
            &serde_json::json!({
                a.to_string(): {"internal_endpoint": "http://otel-a.svc:3014", "credential_file": ta},
                b.to_string(): {"internal_endpoint": "http://otel-b.svc:3014", "credential_file": tb},
            }),
        );
        let source = LeanOtelRouteSource::from_file(&routes_path);
        assert_eq!(source.current().len(), 2);
        std::fs::remove_file(&tb).unwrap();
        source.reload();
        assert!(source.current().route(b).is_none(), "token gone: route dropped");
        assert!(source.current().route(a).is_some(), "the other tenant is untouched");
        // It comes back when the token does.
        rotate(dir.path(), "b", &"b".repeat(48));
        source.reload();
        assert!(source.current().route(b).is_some());
    }

    /// NAN-3531: a token rotated at the same path publishes a new map, which
    /// makes the OTLP client cache rebuild and re-read the token.
    #[test]
    fn a_token_rotation_at_the_same_path_publishes_a_new_map() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::now_v7();
        let file = token(dir.path(), "t");
        let routes_path = dir.path().join("routes.json");
        write_routes(
            &routes_path,
            &serde_json::json!({ tenant.to_string(): {"internal_endpoint": "http://o.svc:3014", "credential_file": file} }),
        );
        let source = LeanOtelRouteSource::from_file(&routes_path);
        let before = source.current();
        rotate(dir.path(), "t", &"r".repeat(48));
        source.reload();
        let after = source.current();
        assert!(!Arc::ptr_eq(&before, &after), "a rotation must publish a new map");
        assert_eq!(after.route(tenant), before.route(tenant), "same route, new token");
        assert_eq!(std::fs::read_to_string(&after.route(tenant).unwrap().credential_file).unwrap(), "r".repeat(48));
    }

    /// A token that exists but is not private is dropped, and admitted once
    /// it is made private: a permission fix changes no inode or mtime, so the
    /// retry rides the "last parse dropped an entry" rule.
    #[cfg(unix)]
    #[test]
    fn a_dropped_route_is_retried_after_its_token_becomes_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::now_v7();
        let file = dir.path().join("t");
        std::fs::write(&file, "t".repeat(48)).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let routes_path = dir.path().join("routes.json");
        write_routes(
            &routes_path,
            &serde_json::json!({ tenant.to_string(): {"internal_endpoint": "http://o.svc:3014", "credential_file": file} }),
        );
        let source = LeanOtelRouteSource::from_file(&routes_path);
        assert!(source.current().is_empty());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o400)).unwrap();
        source.reload();
        assert!(source.current().route(tenant).is_some());
    }
}
