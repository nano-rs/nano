// SPDX-License-Identifier: AGPL-3.0-or-later

//! Monotonic, multi-node publication for generated Vector configuration.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ed25519_dalek::{pkcs8::DecodePrivateKey, Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{
    cmp::Ordering,
    collections::BTreeSet,
    env::VarError,
    path::{Component, Path, PathBuf},
};
use thiserror::Error;
use tokio::fs;
use uuid::Uuid;

const MANIFEST_VERSION: u32 = 1;
const RENDERER_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_SNAPSHOT_FILES: usize = 10_000;
const MAX_SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;
const MAX_SNAPSHOT_PATH_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROTOCOL_FILE_BYTES: usize = 16 * 1024 * 1024;
const LOCAL_GENERATION_RETENTION: usize = 3;
const MANIFEST_FILE: &str = "_manifest.json";
const CHECKSUMS_FILE: &str = "_checksums.sha256";
const ENVELOPE_FILE: &str = "_envelope.json";
const ENVELOPE_SIGNATURE_FILE: &str = "_envelope.sig";
const READY_FILE: &str = ".ready";

#[derive(Debug, Error)]
pub enum VectorConfigPublicationError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("snapshot serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid snapshot path: {0}")]
    InvalidPath(String),
    #[error(
        "Vector config render diverged for source revision {source_revision}: committed {committed_hash}, rendered {rendered_hash}"
    )]
    DivergentRender {
        source_revision: i64,
        committed_hash: String,
        rendered_hash: String,
    },
    #[error("Vector config publication state is missing")]
    MissingState,
    #[error("Vector config snapshot exceeds safety limit: {0}")]
    SnapshotLimit(String),
    #[error("invalid Vector config renderer version '{version}': {message}")]
    InvalidRendererVersion { version: String, message: String },
    #[error("invalid VECTOR_CONFIG_RENDERER_EPOCH '{value}': {message}")]
    InvalidRendererEpoch { value: String, message: String },
    #[error("invalid VECTOR_CONFIG_SIGNING_PRIVATE_KEY_B64: {0}")]
    InvalidSigningKey(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationOutcome {
    Published {
        generation: i64,
        source_revision: i64,
    },
    Reused {
        generation: i64,
        source_revision: i64,
    },
    Stale {
        expected_revision: i64,
        actual_revision: i64,
    },
    SupersededRenderer {
        running_epoch: i64,
        running_version: String,
        committed_epoch: i64,
        committed_version: String,
        /// NAN-1777 (def-4): whether the source has advanced past what is
        /// published (`source_revision > published_source_revision`). When true,
        /// this older renderer being superseded means real parser/source edits
        /// are frozen and will never reach Vector until the renderer catches up
        /// (bump `VECTOR_CONFIG_RENDERER_EPOCH`), so the reconciler logs at WARN.
        /// When false there is no pending work and the supersede is benign.
        pending_work: bool,
    },
}

impl PublicationOutcome {
    pub fn generation(&self) -> Option<i64> {
        match self {
            Self::Published { generation, .. } | Self::Reused { generation, .. } => {
                Some(*generation)
            }
            Self::Stale { .. } | Self::SupersededRenderer { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotManifestEntry {
    pub path: String,
    pub sha256: String,
    pub size: usize,
}

#[derive(Clone)]
struct SnapshotFile {
    path: String,
    bytes: Vec<u8>,
    sha256: String,
}

/// An in-memory canonical snapshot. File bytes are deliberately omitted from
/// Debug/Serialize so generated credentials cannot leak through logs or DB
/// metadata; the database stores only path/size metadata and one aggregate
/// content hash, never plaintext or per-file secret-derived hashes.
#[derive(Clone)]
pub struct SnapshotBundle {
    content_hash: String,
    manifest: Vec<SnapshotManifestEntry>,
    files: Vec<SnapshotFile>,
}

impl SnapshotBundle {
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    pub fn manifest(&self) -> &[SnapshotManifestEntry] {
        &self.manifest
    }
}

#[derive(Debug, Serialize)]
struct StoredManifest<'a> {
    version: u32,
    renderer_epoch: i64,
    renderer_version: &'a str,
    files: Vec<StoredManifestEntry<'a>>,
}

#[derive(Debug, Serialize)]
struct StoredManifestEntry<'a> {
    path: &'a str,
    size: usize,
}

#[derive(Debug, Serialize)]
struct LocalManifest<'a> {
    version: u32,
    generation: i64,
    source_revision: i64,
    renderer_epoch: i64,
    renderer_version: &'a str,
    content_hash: &'a str,
    files: &'a [SnapshotManifestEntry],
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterializedManifest {
    version: u32,
    generation: i64,
    source_revision: i64,
    renderer_epoch: i64,
    renderer_version: String,
    content_hash: String,
    files: Vec<SnapshotManifestEntry>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PublicationEnvelope {
    version: u32,
    generation: i64,
    source_revision: i64,
    renderer_epoch: i64,
    renderer_version: String,
    content_hash: String,
    checksums_sha256: String,
}

struct RendererRuntime {
    epoch: i64,
    signing_key: Option<SigningKey>,
}

#[derive(Clone)]
pub struct VectorConfigPublisher {
    pool: PgPool,
    config_dir: PathBuf,
    node_id: String,
}

#[derive(Debug)]
struct PublicationState {
    source_revision: i64,
    published_source_revision: i64,
    current_generation: Option<i64>,
    current_content_hash: Option<String>,
    current_renderer_epoch: i64,
    current_renderer_version: String,
}

#[derive(Debug, PartialEq, Eq)]
enum PublicationDecision {
    Stale {
        actual_revision: i64,
    },
    SupersededRenderer {
        committed_epoch: i64,
        committed_version: String,
    },
    Reuse {
        generation: i64,
    },
    PublishNew,
}

impl VectorConfigPublisher {
    pub fn new(pool: PgPool, config_dir: impl AsRef<Path>, node_id: impl Into<String>) -> Self {
        Self {
            pool,
            config_dir: config_dir.as_ref().to_path_buf(),
            node_id: node_id.into(),
        }
    }

    pub async fn source_revision(&self) -> Result<i64, VectorConfigPublicationError> {
        sqlx::query_scalar(
            "SELECT source_revision FROM vector_config_publication_state WHERE singleton = TRUE",
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(VectorConfigPublicationError::MissingState)
    }

    /// Return the committed outcome when this API pod already has the current
    /// generation materialized. The periodic reconciler uses this inexpensive
    /// check to avoid re-rendering every parser and rewriting credentials when
    /// neither the database nor the pod-local emptyDir changed.
    pub async fn local_current_outcome(
        &self,
    ) -> Result<Option<PublicationOutcome>, VectorConfigPublicationError> {
        let runtime = renderer_runtime()?;
        let state = sqlx::query_as::<_, (i64, i64, Option<i64>, Option<String>, i64, String)>(
            "SELECT source_revision, published_source_revision, current_generation, current_content_hash, \
                    current_renderer_epoch, current_renderer_version \
             FROM vector_config_publication_state WHERE singleton = TRUE",
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(VectorConfigPublicationError::MissingState)?;

        match compare_renderer_precedence(runtime.epoch, RENDERER_VERSION, state.4, &state.5)? {
            Ordering::Less => {
                return Ok(Some(PublicationOutcome::SupersededRenderer {
                    running_epoch: runtime.epoch,
                    running_version: RENDERER_VERSION.to_string(),
                    committed_epoch: state.4,
                    committed_version: state.5,
                    // source_revision (state.0) vs published_source_revision (state.1)
                    pending_work: state.0 > state.1,
                }));
            }
            Ordering::Greater => return Ok(None),
            Ordering::Equal => {}
        }
        if state.0 != state.1 {
            return Ok(None);
        }
        let Some(generation) = state.2 else {
            return Ok(None);
        };
        let Some(content_hash) = state.3 else {
            return Ok(None);
        };
        let verifying_key = runtime.signing_key.as_ref().map(SigningKey::verifying_key);
        let destination = self
            .config_dir
            .join("publications")
            .join(format!("{generation:020}"));
        if !materialized_generation_matches(
            &destination,
            generation,
            state.0,
            &content_hash,
            runtime.epoch,
            RENDERER_VERSION,
            verifying_key.as_ref(),
        )
        .await?
        {
            return Ok(None);
        }

        Ok(Some(PublicationOutcome::Reused {
            generation,
            source_revision: state.0,
        }))
    }

    /// Allocate an isolated render root beneath the API's emptyDir. Nothing in
    /// this tree is visible to upload sidecars until `publish` commits and
    /// materializes a ready generation.
    pub async fn create_render_dir(&self) -> Result<PathBuf, VectorConfigPublicationError> {
        let staging_root = self.config_dir.join(".publication-staging");
        fs::create_dir_all(&staging_root).await?;
        remove_directory_children(&staging_root).await?;
        let root = staging_root.join(Uuid::new_v4().to_string());
        fs::create_dir_all(root.join("sources/parsers")).await?;
        fs::create_dir_all(root.join("sources/configs")).await?;
        Ok(root)
    }

    pub async fn prepare_snapshot(
        &self,
        sources_dir: impl AsRef<Path>,
    ) -> Result<SnapshotBundle, VectorConfigPublicationError> {
        let sources_dir = sources_dir.as_ref().to_path_buf();
        tokio::task::spawn_blocking(move || build_snapshot(&sources_dir))
            .await
            .map_err(|e| {
                VectorConfigPublicationError::Io(std::io::Error::other(format!(
                    "snapshot worker failed: {e}"
                )))
            })?
    }

    /// Commit a rendered snapshot only if `expected_revision` is still the
    /// database source revision. The singleton row lock is the current-pointer
    /// CAS: delayed publishers cannot move it backwards. Renderers from the
    /// same renderer identity must produce the same hash. A higher explicit
    /// epoch wins first (including an intentional semantic-version rollback);
    /// semantic versions order renderers only within the same epoch.
    pub async fn publish(
        &self,
        expected_revision: i64,
        snapshot: &SnapshotBundle,
    ) -> Result<PublicationOutcome, VectorConfigPublicationError> {
        let runtime = renderer_runtime()?;
        let mut tx = self.pool.begin().await?;
        let state = sqlx::query_as::<_, (i64, i64, Option<i64>, Option<String>, i64, String)>(
            "SELECT source_revision, published_source_revision, current_generation, current_content_hash, \
                    current_renderer_epoch, current_renderer_version \
             FROM vector_config_publication_state WHERE singleton = TRUE FOR UPDATE",
        )
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(VectorConfigPublicationError::MissingState)?;

        let state = PublicationState {
            source_revision: state.0,
            published_source_revision: state.1,
            current_generation: state.2,
            current_content_hash: state.3,
            current_renderer_epoch: state.4,
            current_renderer_version: state.5,
        };
        match decide_publication(
            &state,
            expected_revision,
            &snapshot.content_hash,
            runtime.epoch,
            RENDERER_VERSION,
        )? {
            PublicationDecision::Stale { actual_revision } => {
                tx.rollback().await?;
                return Ok(PublicationOutcome::Stale {
                    expected_revision,
                    actual_revision,
                });
            }
            PublicationDecision::SupersededRenderer {
                committed_epoch,
                committed_version,
            } => {
                tx.rollback().await?;
                return Ok(PublicationOutcome::SupersededRenderer {
                    running_epoch: runtime.epoch,
                    running_version: RENDERER_VERSION.to_string(),
                    committed_epoch,
                    committed_version,
                    pending_work: state.source_revision > state.published_source_revision,
                });
            }
            PublicationDecision::Reuse { generation } => {
                tx.commit().await?;
                self.materialize(
                    generation,
                    expected_revision,
                    runtime.epoch,
                    snapshot,
                    runtime.signing_key.as_ref(),
                )
                .await?;
                return Ok(PublicationOutcome::Reused {
                    generation,
                    source_revision: expected_revision,
                });
            }
            PublicationDecision::PublishNew => {}
        }

        let generation: i64 =
            sqlx::query_scalar("SELECT nextval('vector_config_generation_seq')::BIGINT")
                .fetch_one(&mut *tx)
                .await?;
        let stored_manifest = serde_json::to_value(StoredManifest {
            version: MANIFEST_VERSION,
            renderer_epoch: runtime.epoch,
            renderer_version: RENDERER_VERSION,
            files: snapshot
                .manifest
                .iter()
                .map(|entry| StoredManifestEntry {
                    path: &entry.path,
                    size: entry.size,
                })
                .collect(),
        })?;

        sqlx::query(
            "INSERT INTO vector_config_snapshots \
             (generation, source_revision, renderer_epoch, renderer_version, content_hash, manifest, created_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(generation)
        .bind(expected_revision)
        .bind(runtime.epoch)
        .bind(RENDERER_VERSION)
        .bind(&snapshot.content_hash)
        .bind(stored_manifest)
        .bind(&self.node_id)
        .execute(&mut *tx)
        .await?;

        let advanced = sqlx::query(
            "UPDATE vector_config_publication_state \
             SET published_source_revision = $1, current_generation = $2, \
                 current_content_hash = $3, current_renderer_epoch = $4, \
                 current_renderer_version = $5, updated_at = NOW() \
             WHERE singleton = TRUE AND source_revision = $1",
        )
        .bind(expected_revision)
        .bind(generation)
        .bind(&snapshot.content_hash)
        .bind(runtime.epoch)
        .bind(RENDERER_VERSION)
        .execute(&mut *tx)
        .await?;

        if advanced.rows_affected() != 1 {
            tx.rollback().await?;
            let actual_revision = self.source_revision().await?;
            return Ok(PublicationOutcome::Stale {
                expected_revision,
                actual_revision,
            });
        }

        tx.commit().await?;
        self.materialize(
            generation,
            expected_revision,
            runtime.epoch,
            snapshot,
            runtime.signing_key.as_ref(),
        )
        .await?;
        Ok(PublicationOutcome::Published {
            generation,
            source_revision: expected_revision,
        })
    }

    pub async fn cleanup_render_dir(&self, path: &Path) {
        let staging_root = self.config_dir.join(".publication-staging");
        let valid_child = path.parent() == Some(staging_root.as_path())
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| Uuid::parse_str(name).ok())
                .is_some();
        if !valid_child {
            tracing::error!(path = %path.display(), "refusing to clean an invalid Vector render path");
            return;
        }
        if let Err(error) = fs::remove_dir_all(path).await {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %path.display(), %error, "failed to clean Vector render directory");
            }
        }
    }

    async fn materialize(
        &self,
        generation: i64,
        source_revision: i64,
        renderer_epoch: i64,
        snapshot: &SnapshotBundle,
        signing_key: Option<&SigningKey>,
    ) -> Result<(), VectorConfigPublicationError> {
        let publications = self.config_dir.join("publications");
        fs::create_dir_all(&publications).await?;
        remove_abandoned_materializations(&publications).await?;
        let generation_name = format!("{generation:020}");
        let destination = publications.join(&generation_name);
        let verifying_key = signing_key.map(SigningKey::verifying_key);

        if materialized_generation_matches(
            &destination,
            generation,
            source_revision,
            &snapshot.content_hash,
            renderer_epoch,
            RENDERER_VERSION,
            verifying_key.as_ref(),
        )
        .await?
        {
            return Ok(());
        }
        remove_path_if_present(&destination).await?;

        let temporary = publications.join(format!(".{generation_name}.tmp-{}", Uuid::new_v4()));
        fs::create_dir_all(&temporary).await?;

        for file in &snapshot.files {
            let path = temporary.join(&file.path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).await?;
            }
            fs::write(path, &file.bytes).await?;
        }

        let checksums = snapshot
            .files
            .iter()
            .map(|file| format!("{}  {}\n", file.sha256, file.path))
            .collect::<String>()
            .into_bytes();
        fs::write(temporary.join(CHECKSUMS_FILE), &checksums).await?;
        fs::write(
            temporary.join(MANIFEST_FILE),
            serde_json::to_vec_pretty(&LocalManifest {
                version: MANIFEST_VERSION,
                generation,
                source_revision,
                renderer_epoch,
                renderer_version: RENDERER_VERSION,
                content_hash: &snapshot.content_hash,
                files: &snapshot.manifest,
            })?,
        )
        .await?;

        if let Some(signing_key) = signing_key {
            let (envelope, signature) = signed_envelope(
                generation,
                source_revision,
                renderer_epoch,
                RENDERER_VERSION,
                &snapshot.content_hash,
                &checksums,
                signing_key,
            )?;
            fs::write(temporary.join(ENVELOPE_FILE), envelope).await?;
            fs::write(temporary.join(ENVELOPE_SIGNATURE_FILE), signature).await?;
        }

        fs::write(
            temporary.join(READY_FILE),
            ready_marker(
                generation,
                source_revision,
                renderer_epoch,
                RENDERER_VERSION,
                &snapshot.content_hash,
            ),
        )
        .await?;

        match fs::rename(&temporary, &destination).await {
            Ok(()) => {}
            Err(_) => {
                if materialized_generation_matches(
                    &destination,
                    generation,
                    source_revision,
                    &snapshot.content_hash,
                    renderer_epoch,
                    RENDERER_VERSION,
                    verifying_key.as_ref(),
                )
                .await?
                {
                    fs::remove_dir_all(&temporary).await?;
                } else {
                    remove_path_if_present(&destination).await?;
                    fs::rename(&temporary, &destination).await?;
                }
            }
        }

        self.prune_local_generations(&publications).await;
        Ok(())
    }

    async fn prune_local_generations(&self, publications: &Path) {
        let mut entries = match fs::read_dir(publications).await {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(%error, "failed to scan local Vector config generations");
                return;
            }
        };
        let mut generations = Vec::new();
        loop {
            match entries.next_entry().await {
                Ok(Some(entry)) => {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.len() == 20
                        && name.bytes().all(|byte| byte.is_ascii_digit())
                        && name.parse::<i64>().is_ok_and(|generation| generation > 0)
                        && fs::try_exists(entry.path().join(READY_FILE))
                            .await
                            .unwrap_or(false)
                    {
                        generations.push((name, entry.path()));
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    tracing::warn!(%error, "failed while scanning local Vector config generations");
                    return;
                }
            }
        }
        generations.sort_by(|left, right| left.0.cmp(&right.0));
        let remove_count = generations.len().saturating_sub(LOCAL_GENERATION_RETENTION);
        for (_, path) in generations.into_iter().take(remove_count) {
            if let Err(error) = fs::remove_dir_all(&path).await {
                tracing::warn!(path = %path.display(), %error, "failed to prune old local Vector config generation");
            }
        }
    }
}

async fn remove_path_if_present(path: &Path) -> Result<(), VectorConfigPublicationError> {
    let metadata = match fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_dir() {
        fs::remove_dir_all(path).await?;
    } else {
        fs::remove_file(path).await?;
    }
    Ok(())
}

async fn remove_directory_children(root: &Path) -> Result<(), VectorConfigPublicationError> {
    let mut entries = fs::read_dir(root).await?;
    while let Some(entry) = entries.next_entry().await? {
        remove_path_if_present(&entry.path()).await?;
    }
    Ok(())
}

async fn remove_abandoned_materializations(
    publications: &Path,
) -> Result<(), VectorConfigPublicationError> {
    let mut entries = fs::read_dir(publications).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') && name.contains(".tmp-") {
            remove_path_if_present(&entry.path()).await?;
        }
    }
    Ok(())
}

async fn materialized_generation_matches(
    directory: &Path,
    generation: i64,
    source_revision: i64,
    content_hash: &str,
    renderer_epoch: i64,
    renderer_version: &str,
    verifying_key: Option<&VerifyingKey>,
) -> Result<bool, VectorConfigPublicationError> {
    let Some((actual_files, actual_directories)) = collect_materialized_tree(directory).await?
    else {
        return Ok(false);
    };

    let Some(manifest_bytes) =
        read_bounded_regular_file(&directory.join(MANIFEST_FILE), MAX_PROTOCOL_FILE_BYTES).await?
    else {
        return Ok(false);
    };
    let manifest: MaterializedManifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(_) => return Ok(false),
    };
    if manifest.version != MANIFEST_VERSION
        || manifest.generation != generation
        || manifest.source_revision != source_revision
        || manifest.renderer_epoch != renderer_epoch
        || manifest.content_hash != content_hash
        || manifest.renderer_version != renderer_version
        || manifest.files.is_empty()
        || manifest.files.len() > MAX_SNAPSHOT_FILES
    {
        return Ok(false);
    }

    let mut expected_files = BTreeSet::from([
        MANIFEST_FILE.to_string(),
        CHECKSUMS_FILE.to_string(),
        READY_FILE.to_string(),
    ]);
    if verifying_key.is_some() {
        expected_files.insert(ENVELOPE_FILE.to_string());
        expected_files.insert(ENVELOPE_SIGNATURE_FILE.to_string());
    }
    let mut expected_directories = BTreeSet::new();
    let mut previous_path: Option<&str> = None;
    let mut total_bytes = 0usize;
    let mut total_path_bytes = 0usize;
    for entry in &manifest.files {
        let path = Path::new(&entry.path);
        if validate_relative_path(path).is_err()
            || !is_safe_manifest_path(&entry.path)
            || is_reserved_materialization_path(&entry.path)
            || previous_path.is_some_and(|previous| previous >= entry.path.as_str())
            || entry.sha256.len() != 64
            || !entry
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Ok(false);
        }
        previous_path = Some(&entry.path);
        total_path_bytes = match total_path_bytes.checked_add(entry.path.len()) {
            Some(total) if total <= MAX_SNAPSHOT_PATH_BYTES => total,
            _ => return Ok(false),
        };
        if !expected_files.insert(entry.path.clone()) {
            return Ok(false);
        }
        let mut parent = path.parent();
        while let Some(parent_path) = parent {
            if parent_path.as_os_str().is_empty() {
                break;
            }
            let Some(directory) = normalized_relative_path(parent_path) else {
                return Ok(false);
            };
            expected_directories.insert(directory);
            parent = parent_path.parent();
        }
        total_bytes = match total_bytes.checked_add(entry.size) {
            Some(total) if total <= MAX_SNAPSHOT_BYTES => total,
            _ => return Ok(false),
        };
    }
    if actual_files != expected_files || actual_directories != expected_directories {
        return Ok(false);
    }

    let Some(checksums) =
        read_bounded_regular_file(&directory.join(CHECKSUMS_FILE), MAX_PROTOCOL_FILE_BYTES).await?
    else {
        return Ok(false);
    };
    let expected_checksums = manifest
        .files
        .iter()
        .map(|file| format!("{}  {}\n", file.sha256, file.path))
        .collect::<String>()
        .into_bytes();
    if checksums != expected_checksums {
        return Ok(false);
    }

    let mut aggregate = Sha256::new();
    for entry in &manifest.files {
        let Some(bytes) =
            read_bounded_regular_file(&directory.join(&entry.path), MAX_SNAPSHOT_BYTES).await?
        else {
            return Ok(false);
        };
        if bytes.len() != entry.size || hex::encode(Sha256::digest(&bytes)) != entry.sha256 {
            return Ok(false);
        }
        update_content_hash(&mut aggregate, &entry.path, &bytes);
    }
    if hex::encode(aggregate.finalize()) != content_hash {
        return Ok(false);
    }

    let Some(ready) = read_bounded_regular_file(&directory.join(READY_FILE), 1024).await? else {
        return Ok(false);
    };
    if ready
        != ready_marker(
            generation,
            source_revision,
            renderer_epoch,
            renderer_version,
            content_hash,
        )
    {
        return Ok(false);
    }

    if let Some(verifying_key) = verifying_key {
        let Some(envelope) =
            read_bounded_regular_file(&directory.join(ENVELOPE_FILE), 4096).await?
        else {
            return Ok(false);
        };
        let Some(signature) =
            read_bounded_regular_file(&directory.join(ENVELOPE_SIGNATURE_FILE), 1024).await?
        else {
            return Ok(false);
        };
        if !verify_envelope(
            &envelope,
            &signature,
            generation,
            source_revision,
            renderer_epoch,
            renderer_version,
            content_hash,
            &checksums,
            verifying_key,
        ) {
            return Ok(false);
        }
    }

    Ok(true)
}

fn decide_publication(
    state: &PublicationState,
    expected_revision: i64,
    rendered_hash: &str,
    renderer_epoch: i64,
    renderer_version: &str,
) -> Result<PublicationDecision, VectorConfigPublicationError> {
    if state.source_revision != expected_revision
        || state.published_source_revision > expected_revision
    {
        return Ok(PublicationDecision::Stale {
            actual_revision: state.source_revision,
        });
    }

    match compare_renderer_precedence(
        renderer_epoch,
        renderer_version,
        state.current_renderer_epoch,
        &state.current_renderer_version,
    )? {
        Ordering::Less => {
            return Ok(PublicationDecision::SupersededRenderer {
                committed_epoch: state.current_renderer_epoch,
                committed_version: state.current_renderer_version.clone(),
            });
        }
        Ordering::Greater => return Ok(PublicationDecision::PublishNew),
        Ordering::Equal => {}
    }

    if state.published_source_revision == expected_revision {
        let generation = state
            .current_generation
            .ok_or(VectorConfigPublicationError::MissingState)?;
        let committed_hash = state
            .current_content_hash
            .as_ref()
            .ok_or(VectorConfigPublicationError::MissingState)?;
        if committed_hash != rendered_hash {
            return Err(VectorConfigPublicationError::DivergentRender {
                source_revision: expected_revision,
                committed_hash: committed_hash.clone(),
                rendered_hash: rendered_hash.to_string(),
            });
        }
        return Ok(PublicationDecision::Reuse { generation });
    }

    Ok(PublicationDecision::PublishNew)
}

fn compare_renderer_precedence(
    running_epoch: i64,
    running_version: &str,
    committed_epoch: i64,
    committed_version: &str,
) -> Result<Ordering, VectorConfigPublicationError> {
    match running_epoch.cmp(&committed_epoch) {
        Ordering::Equal => Ok(parse_renderer_version(running_version)?
            .cmp(&parse_renderer_version(committed_version)?)),
        ordering => Ok(ordering),
    }
}

fn renderer_runtime() -> Result<RendererRuntime, VectorConfigPublicationError> {
    Ok(RendererRuntime {
        epoch: renderer_epoch_from_env()?,
        signing_key: signing_key_from_env()?,
    })
}

fn renderer_epoch_from_env() -> Result<i64, VectorConfigPublicationError> {
    match std::env::var("VECTOR_CONFIG_RENDERER_EPOCH") {
        Ok(value) => parse_renderer_epoch(&value),
        Err(VarError::NotPresent) => Ok(0),
        Err(VarError::NotUnicode(_)) => Err(VectorConfigPublicationError::InvalidRendererEpoch {
            value: "<non-UTF-8>".to_string(),
            message: "value must be a non-negative integer".to_string(),
        }),
    }
}

fn parse_renderer_epoch(value: &str) -> Result<i64, VectorConfigPublicationError> {
    value
        .parse::<i64>()
        .ok()
        .filter(|epoch| *epoch >= 0)
        .ok_or_else(|| VectorConfigPublicationError::InvalidRendererEpoch {
            value: value.to_string(),
            message: "value must be a non-negative 64-bit integer".to_string(),
        })
}

fn signing_key_from_env() -> Result<Option<SigningKey>, VectorConfigPublicationError> {
    match std::env::var("VECTOR_CONFIG_SIGNING_PRIVATE_KEY_B64") {
        Ok(value) => signing_key_from_optional_encoded(Some(&value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(VectorConfigPublicationError::InvalidSigningKey(
            "environment value is not valid UTF-8".to_string(),
        )),
    }
}

/// Map an optional base64-encoded signing key to a runtime key.
///
/// NAN-1777 (def-5): a present-but-empty or whitespace-only value means the key
/// is simply ABSENT (publication stays disabled), not misconfigured. The compose
/// template always emits `VECTOR_CONFIG_SIGNING_PRIVATE_KEY_B64: ${…}`, so a
/// pre-existing tenant `.env` expands it to an empty string; the k8s manifest
/// exposes it as an `optional` secret key that resolves empty until provisioned.
/// Previously both of those mapped to `InvalidSigningKey`, which failed
/// `renderer_runtime()` and silently froze every reconcile at warn. Treat empty
/// as `None` so publication is cleanly disabled instead. Surrounding whitespace
/// on a real key (e.g. a trailing newline from a mounted secret) is trimmed.
fn signing_key_from_optional_encoded(
    encoded: Option<&str>,
) -> Result<Option<SigningKey>, VectorConfigPublicationError> {
    match encoded.map(str::trim) {
        None | Some("") => Ok(None),
        Some(trimmed) => decode_signing_key(trimmed).map(Some),
    }
}

fn decode_signing_key(encoded: &str) -> Result<SigningKey, VectorConfigPublicationError> {
    let der = BASE64_STANDARD.decode(encoded).map_err(|error| {
        VectorConfigPublicationError::InvalidSigningKey(format!("invalid base64: {error}"))
    })?;
    SigningKey::from_pkcs8_der(&der).map_err(|error| {
        VectorConfigPublicationError::InvalidSigningKey(format!(
            "invalid Ed25519 PKCS#8 DER: {error}"
        ))
    })
}

fn ready_marker(
    generation: i64,
    source_revision: i64,
    renderer_epoch: i64,
    renderer_version: &str,
    content_hash: &str,
) -> Vec<u8> {
    format!(
        "generation={generation}\nsource_revision={source_revision}\nrenderer_epoch={renderer_epoch}\nrenderer_version={renderer_version}\ncontent_hash={content_hash}\n"
    )
    .into_bytes()
}

fn expected_envelope(
    generation: i64,
    source_revision: i64,
    renderer_epoch: i64,
    renderer_version: &str,
    content_hash: &str,
    checksums: &[u8],
) -> PublicationEnvelope {
    PublicationEnvelope {
        version: MANIFEST_VERSION,
        generation,
        source_revision,
        renderer_epoch,
        renderer_version: renderer_version.to_string(),
        content_hash: content_hash.to_string(),
        checksums_sha256: hex::encode(Sha256::digest(checksums)),
    }
}

fn signed_envelope(
    generation: i64,
    source_revision: i64,
    renderer_epoch: i64,
    renderer_version: &str,
    content_hash: &str,
    checksums: &[u8],
    signing_key: &SigningKey,
) -> Result<(Vec<u8>, Vec<u8>), VectorConfigPublicationError> {
    let envelope = serde_json::to_vec(&expected_envelope(
        generation,
        source_revision,
        renderer_epoch,
        renderer_version,
        content_hash,
        checksums,
    ))?;
    let signature = BASE64_STANDARD
        .encode(signing_key.sign(&envelope).to_bytes())
        .into_bytes();
    Ok((envelope, signature))
}

#[allow(clippy::too_many_arguments)]
fn verify_envelope(
    envelope: &[u8],
    encoded_signature: &[u8],
    generation: i64,
    source_revision: i64,
    renderer_epoch: i64,
    renderer_version: &str,
    content_hash: &str,
    checksums: &[u8],
    verifying_key: &VerifyingKey,
) -> bool {
    let signature = BASE64_STANDARD
        .decode(encoded_signature)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok());
    if !signature.is_some_and(|signature| verifying_key.verify_strict(envelope, &signature).is_ok())
    {
        return false;
    }
    serde_json::from_slice::<PublicationEnvelope>(envelope).is_ok_and(|actual| {
        actual
            == expected_envelope(
                generation,
                source_revision,
                renderer_epoch,
                renderer_version,
                content_hash,
                checksums,
            )
    })
}

async fn collect_materialized_tree(
    root: &Path,
) -> Result<Option<(BTreeSet<String>, BTreeSet<String>)>, VectorConfigPublicationError> {
    let root_metadata = match fs::symlink_metadata(root).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !root_metadata.file_type().is_dir() {
        return Ok(None);
    }

    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut pending = vec![(root.to_path_buf(), PathBuf::new())];
    while let Some((absolute_directory, relative_directory)) = pending.pop() {
        let mut entries = fs::read_dir(&absolute_directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            let relative = relative_directory.join(entry.file_name());
            let Some(relative_string) = normalized_relative_path(&relative) else {
                return Ok(None);
            };
            let file_type = entry.file_type().await?;
            if file_type.is_symlink() {
                return Ok(None);
            }
            if file_type.is_dir() {
                if !directories.insert(relative_string) {
                    return Ok(None);
                }
                if directories.len() > MAX_SNAPSHOT_FILES {
                    return Ok(None);
                }
                pending.push((entry.path(), relative));
            } else if file_type.is_file() {
                if !files.insert(relative_string) {
                    return Ok(None);
                }
                if files.len() > MAX_SNAPSHOT_FILES + 5 {
                    return Ok(None);
                }
            } else {
                return Ok(None);
            }
        }
    }
    Ok(Some((files, directories)))
}

async fn read_bounded_regular_file(
    path: &Path,
    maximum: usize,
) -> Result<Option<Vec<u8>>, VectorConfigPublicationError> {
    let metadata = match fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() {
        return Ok(None);
    }
    let Ok(expected_size) = usize::try_from(metadata.len()) else {
        return Ok(None);
    };
    if expected_size > maximum {
        return Ok(None);
    }
    let bytes = match fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if bytes.len() != expected_size {
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn normalized_relative_path(path: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            return None;
        };
        parts.push(part.to_str()?);
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

fn is_reserved_materialization_path(path: &str) -> bool {
    matches!(
        path,
        MANIFEST_FILE | CHECKSUMS_FILE | ENVELOPE_FILE | ENVELOPE_SIGNATURE_FILE | READY_FILE
    ) || path.starts_with(".ready-")
}

fn is_safe_manifest_path(path: &str) -> bool {
    !path.contains('\\') && !path.chars().any(char::is_control)
}

fn update_content_hash(hasher: &mut Sha256, path: &str, bytes: &[u8]) {
    hasher.update(path.as_bytes());
    hasher.update([0]);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn parse_renderer_version(version: &str) -> Result<semver::Version, VectorConfigPublicationError> {
    semver::Version::parse(version).map_err(|error| {
        VectorConfigPublicationError::InvalidRendererVersion {
            version: version.to_string(),
            message: error.to_string(),
        }
    })
}

fn build_snapshot(root: &Path) -> Result<SnapshotBundle, VectorConfigPublicationError> {
    let mut paths = Vec::new();
    collect_regular_files(root, root, &mut paths)?;
    paths.sort();
    if paths.is_empty() {
        return Err(VectorConfigPublicationError::SnapshotLimit(
            "snapshot must contain at least one file".to_string(),
        ));
    }
    if paths.len() > MAX_SNAPSHOT_FILES {
        return Err(VectorConfigPublicationError::SnapshotLimit(format!(
            "{} files exceeds maximum {}",
            paths.len(),
            MAX_SNAPSHOT_FILES
        )));
    }

    let mut content_hasher = Sha256::new();
    let mut files = Vec::with_capacity(paths.len());
    let mut manifest = Vec::with_capacity(paths.len());
    let mut total_bytes = 0usize;
    let mut total_path_bytes = 0usize;

    for relative in paths {
        validate_relative_path(&relative)?;
        let path_string = normalized_relative_path(&relative).ok_or_else(|| {
            VectorConfigPublicationError::InvalidPath(relative.display().to_string())
        })?;
        if !is_safe_manifest_path(&path_string) || is_reserved_materialization_path(&path_string) {
            return Err(VectorConfigPublicationError::InvalidPath(path_string));
        }
        total_path_bytes = total_path_bytes
            .checked_add(path_string.len())
            .filter(|total| *total <= MAX_SNAPSHOT_PATH_BYTES)
            .ok_or_else(|| {
                VectorConfigPublicationError::SnapshotLimit(format!(
                    "snapshot paths exceed maximum {MAX_SNAPSHOT_PATH_BYTES} bytes"
                ))
            })?;
        let absolute = root.join(&relative);
        let raw_size = usize::try_from(std::fs::metadata(&absolute)?.len()).map_err(|_| {
            VectorConfigPublicationError::SnapshotLimit(format!(
                "{} is too large for this platform",
                absolute.display()
            ))
        })?;
        if raw_size > MAX_SNAPSHOT_BYTES.saturating_sub(total_bytes) {
            return Err(VectorConfigPublicationError::SnapshotLimit(format!(
                "snapshot would exceed maximum {MAX_SNAPSHOT_BYTES} bytes"
            )));
        }
        let raw = std::fs::read(absolute)?;
        let bytes = normalize_generated_metadata(&path_string, raw);
        total_bytes = total_bytes.checked_add(bytes.len()).ok_or_else(|| {
            VectorConfigPublicationError::SnapshotLimit("byte count overflow".to_string())
        })?;
        if total_bytes > MAX_SNAPSHOT_BYTES {
            return Err(VectorConfigPublicationError::SnapshotLimit(format!(
                "{total_bytes} bytes exceeds maximum {MAX_SNAPSHOT_BYTES}"
            )));
        }
        let sha256 = hex::encode(Sha256::digest(&bytes));

        update_content_hash(&mut content_hasher, &path_string, &bytes);

        manifest.push(SnapshotManifestEntry {
            path: path_string.clone(),
            sha256: sha256.clone(),
            size: bytes.len(),
        });
        files.push(SnapshotFile {
            path: path_string,
            bytes,
            sha256,
        });
    }

    Ok(SnapshotBundle {
        content_hash: hex::encode(content_hasher.finalize()),
        manifest,
        files,
    })
}

fn collect_regular_files(
    root: &Path,
    directory: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<(), VectorConfigPublicationError> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(VectorConfigPublicationError::InvalidPath(
                entry.path().display().to_string(),
            ));
        }
        if file_type.is_dir() {
            collect_regular_files(root, &entry.path(), output)?;
        } else if file_type.is_file() {
            output.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|_| {
                        VectorConfigPublicationError::InvalidPath(
                            entry.path().display().to_string(),
                        )
                    })?
                    .to_path_buf(),
            );
        }
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<(), VectorConfigPublicationError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(VectorConfigPublicationError::InvalidPath(
            path.display().to_string(),
        ));
    }
    Ok(())
}

fn normalize_generated_metadata(path: &str, bytes: Vec<u8>) -> Vec<u8> {
    if !path.ends_with(".toml") {
        return bytes;
    }
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => return error.into_bytes(),
    };
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            // Every generator writes this metadata in the unindented header
            // (currently line three). Do not rewrite matching text inside an
            // analyst-authored VRL multiline string later in the TOML file.
            if index < 5 && line.starts_with("# Generated at:") {
                "# Generated at: committed database snapshot"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_hash_is_stable_across_generated_timestamps() {
        let first = normalize_generated_metadata(
            "parsers/a.toml",
            b"# Generated at: 2026-07-10T01:00:00Z\n[x]\na = 1\n".to_vec(),
        );
        let second = normalize_generated_metadata(
            "parsers/a.toml",
            b"# Generated at: 2026-07-10T02:00:00Z\n[x]\na = 1\n".to_vec(),
        );
        assert_eq!(first, second);
    }

    #[test]
    fn generated_timestamp_normalization_preserves_embedded_vrl_comments() {
        let input = b"# Parser\n# DO NOT EDIT\n# Generated at: 2026-07-10T01:00:00Z\n\nsource = '''\n# Generated at: analyst-authored marker\n'''\n".to_vec();
        let normalized =
            String::from_utf8(normalize_generated_metadata("parsers/a.toml", input)).unwrap();
        assert!(normalized.contains("# Generated at: committed database snapshot"));
        assert!(normalized.contains("# Generated at: analyst-authored marker"));
    }

    #[test]
    fn non_utf8_toml_is_hashed_without_loss() {
        let normalized = normalize_generated_metadata("parsers/a.toml", vec![0xff, 0xfe]);
        assert_eq!(normalized, vec![0xff, 0xfe]);
    }

    #[test]
    fn relative_paths_cannot_escape_generation_root() {
        assert!(validate_relative_path(Path::new("parsers/a.toml")).is_ok());
        assert!(validate_relative_path(Path::new("../a.toml")).is_err());
        assert!(validate_relative_path(Path::new("/tmp/a.toml")).is_err());
        assert!(!is_safe_manifest_path("parsers/line\nbreak.toml"));
        assert!(!is_safe_manifest_path("parsers/back\\slash.toml"));
    }

    #[test]
    fn empty_snapshot_is_rejected_before_publication() {
        let source_dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            build_snapshot(source_dir.path()),
            Err(VectorConfigPublicationError::SnapshotLimit(_))
        ));
    }

    fn committed_state(
        source_revision: i64,
        published_source_revision: i64,
        content_hash: &str,
        renderer_epoch: i64,
        renderer_version: &str,
    ) -> PublicationState {
        PublicationState {
            source_revision,
            published_source_revision,
            current_generation: Some(7),
            current_content_hash: Some(content_hash.to_string()),
            current_renderer_epoch: renderer_epoch,
            current_renderer_version: renderer_version.to_string(),
        }
    }

    #[test]
    fn delayed_node_cannot_regress_committed_revision() {
        let committed = committed_state(12, 12, "new", 0, RENDERER_VERSION);
        assert_eq!(
            decide_publication(&committed, 11, "old", 0, RENDERER_VERSION).unwrap(),
            PublicationDecision::Stale {
                actual_revision: 12
            }
        );
    }

    #[test]
    fn restarted_node_reuses_identical_committed_generation() {
        let committed = committed_state(12, 12, "same", 0, RENDERER_VERSION);
        assert_eq!(
            decide_publication(&committed, 12, "same", 0, RENDERER_VERSION).unwrap(),
            PublicationDecision::Reuse { generation: 7 }
        );
    }

    #[test]
    fn same_revision_with_different_render_is_rejected() {
        let committed = committed_state(12, 12, "node-a", 0, RENDERER_VERSION);
        assert!(matches!(
            decide_publication(&committed, 12, "node-b", 0, RENDERER_VERSION),
            Err(VectorConfigPublicationError::DivergentRender { .. })
        ));
    }

    #[test]
    fn newer_renderer_may_advance_same_database_revision() {
        let committed = committed_state(12, 12, "old-render", 3, "1.2.3");
        assert_eq!(
            decide_publication(&committed, 12, "new-render", 3, "1.2.4").unwrap(),
            PublicationDecision::PublishNew
        );
    }

    #[test]
    fn higher_epoch_allows_intentional_semver_rollback() {
        let committed = committed_state(12, 12, "old-render", 3, "2.0.0");
        assert_eq!(
            decide_publication(&committed, 12, "rollback-render", 4, "1.5.0").unwrap(),
            PublicationDecision::PublishNew
        );
    }

    #[test]
    fn lower_epoch_cannot_advance_even_with_newer_semver() {
        let committed = committed_state(12, 12, "new-epoch", 4, "1.0.0");
        assert_eq!(
            decide_publication(&committed, 12, "old-epoch", 3, "9.0.0").unwrap(),
            PublicationDecision::SupersededRenderer {
                committed_epoch: 4,
                committed_version: "1.0.0".to_string(),
            }
        );
    }

    #[test]
    fn renderer_epoch_parser_rejects_negative_or_malformed_values() {
        assert_eq!(parse_renderer_epoch("0").unwrap(), 0);
        assert_eq!(parse_renderer_epoch("42").unwrap(), 42);
        assert!(parse_renderer_epoch("-1").is_err());
        assert!(parse_renderer_epoch("next").is_err());
    }

    #[test]
    fn newer_source_revision_gets_its_own_generation_even_if_content_matches() {
        let committed = committed_state(13, 12, "same", 0, RENDERER_VERSION);
        assert_eq!(
            decide_publication(&committed, 13, "same", 0, RENDERER_VERSION).unwrap(),
            PublicationDecision::PublishNew
        );
    }

    #[test]
    fn older_renderer_cannot_regress_newer_generation() {
        let committed = committed_state(12, 12, "new-render", 3, "1.2.4");
        assert_eq!(
            decide_publication(&committed, 12, "old-render", 3, "1.2.3").unwrap(),
            PublicationDecision::SupersededRenderer {
                committed_epoch: 3,
                committed_version: "1.2.4".to_string(),
            }
        );
    }

    #[test]
    fn pkcs8_signed_envelope_verifies_and_rejects_tampering() {
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        let original = SigningKey::from_bytes(&[0x31; 32]);
        let der = original.to_pkcs8_der().unwrap();
        let encoded = BASE64_STANDARD.encode(der.as_bytes());
        let signing_key = decode_signing_key(&encoded).unwrap();
        let checksums = b"0123456789abcdef  parsers/test.toml\n";
        let content_hash = "a".repeat(64);
        let (envelope, signature) =
            signed_envelope(9, 12, 4, "1.5.0", &content_hash, checksums, &signing_key).unwrap();

        assert!(verify_envelope(
            &envelope,
            &signature,
            9,
            12,
            4,
            "1.5.0",
            &content_hash,
            checksums,
            &signing_key.verifying_key(),
        ));

        let mut tampered = envelope.clone();
        let last = tampered.last_mut().unwrap();
        *last ^= 1;
        assert!(!verify_envelope(
            &tampered,
            &signature,
            9,
            12,
            4,
            "1.5.0",
            &content_hash,
            checksums,
            &signing_key.verifying_key(),
        ));
    }

    // NAN-1777 (def-5): an absent, empty, or whitespace-only signing key means
    // publication is disabled — not a fatal misconfiguration that freezes
    // reconciliation. Exercises the pure mapping so it stays independent of the
    // process-global env var.
    #[test]
    fn empty_or_whitespace_signing_key_maps_to_none() {
        assert!(signing_key_from_optional_encoded(None).unwrap().is_none());
        assert!(signing_key_from_optional_encoded(Some("")).unwrap().is_none());
        assert!(signing_key_from_optional_encoded(Some("   "))
            .unwrap()
            .is_none());
        assert!(signing_key_from_optional_encoded(Some("\n\t "))
            .unwrap()
            .is_none());
    }

    #[test]
    fn valid_signing_key_decodes_and_tolerates_surrounding_whitespace() {
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        let original = SigningKey::from_bytes(&[0x42; 32]);
        let encoded = BASE64_STANDARD.encode(original.to_pkcs8_der().unwrap().as_bytes());
        let padded = format!("  {encoded}\n");
        let decoded = signing_key_from_optional_encoded(Some(&padded))
            .unwrap()
            .expect("a real key must decode");
        assert_eq!(decoded.to_bytes(), original.to_bytes());
    }

    #[test]
    fn malformed_signing_key_is_still_rejected() {
        assert!(matches!(
            signing_key_from_optional_encoded(Some("not-base64!!")),
            Err(VectorConfigPublicationError::InvalidSigningKey(_))
        ));
    }

    #[tokio::test]
    async fn materialization_repairs_missing_ready_marker() {
        let config_dir = tempfile::tempdir().unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(source_dir.path().join("parsers")).unwrap();
        std::fs::write(
            source_dir.path().join("parsers/example.toml"),
            "[x]\na = 1\n",
        )
        .unwrap();
        let snapshot = build_snapshot(source_dir.path()).unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1/unused")
            .unwrap();
        let publisher = VectorConfigPublisher::new(pool, config_dir.path(), "test-node");

        publisher
            .materialize(3, 7, 0, &snapshot, None)
            .await
            .unwrap();
        let destination = config_dir.path().join("publications/00000000000000000003");
        std::fs::remove_file(destination.join(".ready")).unwrap();

        publisher
            .materialize(3, 7, 0, &snapshot, None)
            .await
            .unwrap();
        assert!(destination.join(".ready").is_file());
        assert!(materialized_generation_matches(
            &destination,
            3,
            7,
            snapshot.content_hash(),
            0,
            RENDERER_VERSION,
            None,
        )
        .await
        .unwrap());
    }

    #[tokio::test]
    async fn materialization_repairs_invalid_ready_generation() {
        let config_dir = tempfile::tempdir().unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(source_dir.path().join("parsers")).unwrap();
        std::fs::write(
            source_dir.path().join("parsers/example.toml"),
            "[x]\na = 1\n",
        )
        .unwrap();
        let snapshot = build_snapshot(source_dir.path()).unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1/unused")
            .unwrap();
        let publisher = VectorConfigPublisher::new(pool, config_dir.path(), "test-node");

        publisher
            .materialize(4, 8, 0, &snapshot, None)
            .await
            .unwrap();
        let destination = config_dir.path().join("publications/00000000000000000004");
        std::fs::write(destination.join("_manifest.json"), b"{}").unwrap();

        publisher
            .materialize(4, 8, 0, &snapshot, None)
            .await
            .unwrap();
        assert!(materialized_generation_matches(
            &destination,
            4,
            8,
            snapshot.content_hash(),
            0,
            RENDERER_VERSION,
            None,
        )
        .await
        .unwrap());
    }

    #[tokio::test]
    async fn materialization_repairs_corrupt_missing_checksum_and_extra_files() {
        let config_dir = tempfile::tempdir().unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(source_dir.path().join("parsers")).unwrap();
        std::fs::write(
            source_dir.path().join("parsers/example.toml"),
            "[x]\na = 1\n",
        )
        .unwrap();
        let snapshot = build_snapshot(source_dir.path()).unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1/unused")
            .unwrap();
        let publisher = VectorConfigPublisher::new(pool, config_dir.path(), "test-node");
        let destination = config_dir.path().join("publications/00000000000000000005");

        publisher
            .materialize(5, 9, 0, &snapshot, None)
            .await
            .unwrap();

        std::fs::write(destination.join("parsers/example.toml"), b"tampered").unwrap();
        assert!(!materialized_generation_matches(
            &destination,
            5,
            9,
            snapshot.content_hash(),
            0,
            RENDERER_VERSION,
            None,
        )
        .await
        .unwrap());
        publisher
            .materialize(5, 9, 0, &snapshot, None)
            .await
            .unwrap();

        std::fs::remove_file(destination.join("parsers/example.toml")).unwrap();
        publisher
            .materialize(5, 9, 0, &snapshot, None)
            .await
            .unwrap();
        assert!(destination.join("parsers/example.toml").is_file());

        std::fs::write(
            destination.join(CHECKSUMS_FILE),
            b"invalid checksum manifest\n",
        )
        .unwrap();
        publisher
            .materialize(5, 9, 0, &snapshot, None)
            .await
            .unwrap();

        std::fs::write(destination.join("unexpected.toml"), b"extra").unwrap();
        std::fs::create_dir(destination.join("empty-extra-directory")).unwrap();
        publisher
            .materialize(5, 9, 0, &snapshot, None)
            .await
            .unwrap();
        assert!(!destination.join("unexpected.toml").exists());
        assert!(!destination.join("empty-extra-directory").exists());
        assert!(materialized_generation_matches(
            &destination,
            5,
            9,
            snapshot.content_hash(),
            0,
            RENDERER_VERSION,
            None,
        )
        .await
        .unwrap());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn materialization_rejects_and_rebuilds_symlinked_payload() {
        use std::os::unix::fs::symlink;

        let config_dir = tempfile::tempdir().unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(source_dir.path().join("parsers")).unwrap();
        std::fs::write(
            source_dir.path().join("parsers/example.toml"),
            "[x]\na = 1\n",
        )
        .unwrap();
        let snapshot = build_snapshot(source_dir.path()).unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1/unused")
            .unwrap();
        let publisher = VectorConfigPublisher::new(pool, config_dir.path(), "test-node");
        let destination = config_dir.path().join("publications/00000000000000000006");

        publisher
            .materialize(6, 10, 0, &snapshot, None)
            .await
            .unwrap();
        let payload = destination.join("parsers/example.toml");
        std::fs::remove_file(&payload).unwrap();
        symlink(source_dir.path().join("parsers/example.toml"), &payload).unwrap();
        assert!(!materialized_generation_matches(
            &destination,
            6,
            10,
            snapshot.content_hash(),
            0,
            RENDERER_VERSION,
            None,
        )
        .await
        .unwrap());

        publisher
            .materialize(6, 10, 0, &snapshot, None)
            .await
            .unwrap();
        assert!(std::fs::symlink_metadata(payload)
            .unwrap()
            .file_type()
            .is_file());
    }

    #[tokio::test]
    async fn signed_materialization_attests_envelope_and_repairs_tampering() {
        let config_dir = tempfile::tempdir().unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(source_dir.path().join("parsers")).unwrap();
        std::fs::write(
            source_dir.path().join("parsers/example.toml"),
            "[x]\na = 1\n",
        )
        .unwrap();
        let snapshot = build_snapshot(source_dir.path()).unwrap();
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let verifying_key = signing_key.verifying_key();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1/unused")
            .unwrap();
        let publisher = VectorConfigPublisher::new(pool, config_dir.path(), "test-node");
        let destination = config_dir.path().join("publications/00000000000000000007");

        publisher
            .materialize(7, 11, 4, &snapshot, Some(&signing_key))
            .await
            .unwrap();
        assert!(materialized_generation_matches(
            &destination,
            7,
            11,
            snapshot.content_hash(),
            4,
            RENDERER_VERSION,
            Some(&verifying_key),
        )
        .await
        .unwrap());

        let envelope_path = destination.join(ENVELOPE_FILE);
        let mut envelope = std::fs::read(&envelope_path).unwrap();
        envelope[0] ^= 1;
        std::fs::write(&envelope_path, envelope).unwrap();
        publisher
            .materialize(7, 11, 4, &snapshot, Some(&signing_key))
            .await
            .unwrap();
        assert!(materialized_generation_matches(
            &destination,
            7,
            11,
            snapshot.content_hash(),
            4,
            RENDERER_VERSION,
            Some(&verifying_key),
        )
        .await
        .unwrap());
    }

    #[tokio::test]
    async fn materialization_bounds_local_generation_retention() {
        let config_dir = tempfile::tempdir().unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(source_dir.path().join("parsers")).unwrap();
        std::fs::write(
            source_dir.path().join("parsers/example.toml"),
            "[x]\na = 1\n",
        )
        .unwrap();
        let snapshot = build_snapshot(source_dir.path()).unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1/unused")
            .unwrap();
        let publisher = VectorConfigPublisher::new(pool, config_dir.path(), "test-node");

        for generation in 1..=5 {
            publisher
                .materialize(generation, generation, 0, &snapshot, None)
                .await
                .unwrap();
        }

        let publications = config_dir.path().join("publications");
        assert!(!publications.join("00000000000000000001").exists());
        assert!(!publications.join("00000000000000000002").exists());
        for generation in 3..=5 {
            assert!(publications.join(format!("{generation:020}")).exists());
        }
    }
}
