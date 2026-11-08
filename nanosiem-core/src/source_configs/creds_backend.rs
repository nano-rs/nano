// SPDX-License-Identifier: AGPL-3.0-or-later

//! Backend for storing source-config credentials.
//!
//! Two backends:
//!   - `Disk`: writes the file under `<config>/sources/` with a `configs__`
//!     prefix. Used for Docker / non-K8s deployments. The prefix exists so the
//!     same file path resolves under K8s ConfigMap key flattening too — see
//!     NAN-664 — though K8s deployments now prefer the Secret backend below.
//!   - `K8sSecret`: PATCHes a tenant-namespace `vector-source-credentials`
//!     Secret that the platform mounts on the Vector pod at
//!     `/etc/vector/source-creds/`. RBAC and mount are set up by the platform
//!     side (FRO-255).
//!
//! The active backend is auto-detected from the in-pod ServiceAccount token
//! file. Set `VECTOR_CREDS_BACKEND=disk|k8s_secret` to override (used in tests
//! and edge cases where the heuristic is wrong).

use std::path::PathBuf;

use super::k8s_secret::{is_in_cluster, K8sSecretClient, K8sSecretError};

/// Name of the Secret in the tenant namespace; contract from FRO-255.
pub(super) const SECRET_NAME: &str = "vector-source-credentials";
/// Mount path the platform sets up on the Vector pod for `SECRET_NAME`.
pub(super) const SECRET_MOUNT_PATH: &str = "/etc/vector/source-creds";
/// Override env var. Values: `disk`, `k8s_secret`. Anything else falls back to
/// auto-detect (token-file presence).
pub(super) const ENV_OVERRIDE: &str = "VECTOR_CREDS_BACKEND";

#[derive(thiserror::Error, Debug)]
pub enum CredsBackendError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("k8s secret error: {0}")]
    K8s(#[from] K8sSecretError),
}

/// Resolved credential storage backend for a `SourceConfigService`.
pub enum CredsBackend {
    Disk {
        config_dir: PathBuf,
        runtime_path: String,
    },
    K8sSecret {
        client: K8sSecretClient,
    },
}

/// The `VECTOR_CREDS_BACKEND` override, normalized to the three values
/// [`CredsBackend::detect`] actually distinguishes.
///
/// The chosen backend decides which credential path is embedded in the
/// generated source TOML, so it is a render-affecting input the publication
/// renderer fingerprint has to cover (NAN-2304). Only the ENV override is
/// visible here — with no override the backend is auto-detected from the
/// in-pod ServiceAccount token file, which is a property of the pod rather
/// than of its configuration, and identical across replicas of one deployment.
pub(crate) fn creds_backend_override_label() -> &'static str {
    match std::env::var(ENV_OVERRIDE).ok().as_deref() {
        Some("k8s_secret") => "k8s_secret",
        Some("disk") => "disk",
        _ => "auto",
    }
}

impl CredsBackend {
    /// Pick a backend based on env override + SA-token-file presence. Disk-
    /// mode arguments are passed in unconditionally so that an explicit
    /// `VECTOR_CREDS_BACKEND=disk` override (or a Docker deployment) lands on
    /// a fully configured Disk variant without further plumbing.
    pub async fn detect(
        config_dir: PathBuf,
        runtime_path: String,
    ) -> Result<Self, CredsBackendError> {
        let want_k8s = match std::env::var(ENV_OVERRIDE).ok().as_deref() {
            Some("k8s_secret") => true,
            Some("disk") => false,
            _ => is_in_cluster(),
        };
        if want_k8s {
            let client = K8sSecretClient::from_pod_env().await?;
            Ok(Self::K8sSecret { client })
        } else {
            Ok(Self::Disk {
                config_dir,
                runtime_path,
            })
        }
    }

    /// Write credential bytes and return the absolute path Vector should embed
    /// in the generated TOML.
    ///
    /// `key` is the canonical storage key (e.g. `gcp_<safe>.creds`). The Disk
    /// backend prefixes it with `configs__` on disk to dodge ConfigMap key
    /// flattening (NAN-664); the K8s backend uses the bare key, since Secret
    /// keys aren't subject to that constraint.
    pub async fn write_creds(
        &self,
        key: &str,
        content: &[u8],
    ) -> Result<String, CredsBackendError> {
        match self {
            Self::Disk {
                config_dir,
                runtime_path,
            } => {
                let filename = format!("configs__{}", key);
                let dir = config_dir.join("sources");
                tokio::fs::create_dir_all(&dir).await?;
                tokio::fs::write(dir.join(&filename), content).await?;
                Ok(format!("{}/{}", runtime_path, filename))
            }
            Self::K8sSecret { client } => {
                client.upsert_key(SECRET_NAME, key, Some(content)).await?;
                Ok(format!("{}/{}", SECRET_MOUNT_PATH, key))
            }
        }
    }

    /// Remove credential bytes for a (now-deleted) source config. Removal is
    /// idempotent in both backends — the disk path is a no-op if the file is
    /// already gone, and strategic-merge null on a missing key is a no-op.
    pub async fn remove_creds(&self, key: &str) -> Result<(), CredsBackendError> {
        match self {
            Self::Disk { config_dir, .. } => {
                let path = config_dir
                    .join("sources")
                    .join(format!("configs__{}", key));
                if tokio::fs::try_exists(&path).await.unwrap_or(false) {
                    tokio::fs::remove_file(&path).await?;
                }
                Ok(())
            }
            Self::K8sSecret { client } => {
                client.upsert_key(SECRET_NAME, key, None).await?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// `VECTOR_CREDS_BACKEND` is process-wide; serialize tests that mutate it
    /// so concurrent runs don't observe each other's overrides.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[tokio::test]
    async fn override_disk_yields_disk_backend() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_OVERRIDE, "disk");
        let backend = CredsBackend::detect(PathBuf::from("/tmp/test"), "/etc/vector".into())
            .await
            .unwrap();
        std::env::remove_var(ENV_OVERRIDE);
        assert!(matches!(backend, CredsBackend::Disk { .. }));
    }

    #[tokio::test]
    async fn disk_backend_emits_configs_double_underscore_path() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = CredsBackend::Disk {
            config_dir: tmp.path().to_path_buf(),
            runtime_path: "/etc/vector/sources".into(),
        };
        let path = backend
            .write_creds("gcp_my_source.creds", b"{\"k\":\"v\"}")
            .await
            .unwrap();
        // Path must be flat under runtime_path with the configs__ prefix —
        // matches the post-NAN-664 layout that survives ConfigMap flattening.
        assert_eq!(path, "/etc/vector/sources/configs__gcp_my_source.creds");
        // File on disk lives at the same flat layout under config_dir/sources/.
        let on_disk = tmp.path().join("sources/configs__gcp_my_source.creds");
        assert!(on_disk.exists(), "expected creds file at {}", on_disk.display());
        assert_eq!(
            tokio::fs::read_to_string(&on_disk).await.unwrap(),
            "{\"k\":\"v\"}"
        );
    }

    #[tokio::test]
    async fn disk_backend_remove_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = CredsBackend::Disk {
            config_dir: tmp.path().to_path_buf(),
            runtime_path: "/etc/vector/sources".into(),
        };
        // Removing a key that was never written must not error.
        backend.remove_creds("gcp_absent.creds").await.unwrap();
        // Write then remove succeeds and reaps the file.
        backend.write_creds("gcp_x.creds", b"x").await.unwrap();
        let path = tmp.path().join("sources/configs__gcp_x.creds");
        assert!(path.exists());
        backend.remove_creds("gcp_x.creds").await.unwrap();
        assert!(!path.exists(), "expected creds file removed");
    }
}
