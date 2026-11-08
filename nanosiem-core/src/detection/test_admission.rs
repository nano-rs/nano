// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-replica admission for interactive detection-rule tests.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use redis::aio::ConnectionManager;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use uuid::Uuid;

const KEY_PREFIX: &str = "nanosiem:rule-test:v1";
const LEASE_TTL_SECS: u64 = 300;
const RENEW_INTERVAL_SECS: u64 = 60;
const REDIS_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);

const RENEW_IF_OWNER_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return 0
"#;

const RELEASE_IF_OWNER_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
"#;

#[derive(Debug, Error)]
pub enum RuleTestAdmissionError {
    #[error("distributed rule-test admission is unavailable")]
    Unavailable,
}

#[derive(Clone)]
enum Backend {
    Local(Arc<DashMap<Uuid, ()>>),
    Redis(Arc<RedisBackend>),
}

struct RedisBackend {
    redis_url: String,
    connection: Mutex<Option<ConnectionManager>>,
}

/// Per-user rule-test admission shared by every API replica when Redis is
/// configured. Without `REDIS_URL`, single-node development uses the original
/// in-process guard.
#[derive(Clone)]
pub struct RuleTestAdmission {
    backend: Backend,
}

impl Default for RuleTestAdmission {
    fn default() -> Self {
        Self::local()
    }
}

impl RuleTestAdmission {
    pub fn local() -> Self {
        Self {
            backend: Backend::Local(Arc::new(DashMap::new())),
        }
    }

    /// Configure distributed admission. A configured backend that cannot be
    /// initialized stays fail-closed; falling back to local admission here
    /// would silently multiply the documented cap by the replica count.
    pub async fn try_with_redis_url(redis_url: &str) -> Self {
        let backend = Arc::new(RedisBackend {
            redis_url: redis_url.to_string(),
            connection: Mutex::new(None),
        });
        if let Err(error) = backend.connection().await {
            // Keep the configured backend and reconnect on later requests. This
            // is fail-closed while Redis is down without requiring an API restart
            // when Dragonfly becomes ready after this pod.
            warn!(%error, "Distributed rule-test admission will retry Redis lazily");
        }
        Self {
            backend: Backend::Redis(backend),
        }
    }

    /// Claim one per-user slot. `Ok(None)` means another request owns it.
    pub async fn acquire(
        &self,
        user_id: Uuid,
    ) -> Result<Option<RuleTestPermit>, RuleTestAdmissionError> {
        match &self.backend {
            Backend::Local(active) => {
                use dashmap::mapref::entry::Entry;
                match active.entry(user_id) {
                    Entry::Occupied(_) => Ok(None),
                    Entry::Vacant(entry) => {
                        entry.insert(());
                        Ok(Some(RuleTestPermit {
                            release: Some(PermitRelease::Local {
                                active: Arc::clone(active),
                                user_id,
                            }),
                        }))
                    }
                }
            }
            Backend::Redis(backend) => {
                let key = format!("{KEY_PREFIX}:{user_id}");
                let owner = Uuid::now_v7().to_string();
                let mut connection = backend.connection().await?;
                let result = tokio::time::timeout(REDIS_OPERATION_TIMEOUT, async {
                    redis::cmd("SET")
                        .arg(&key)
                        .arg(&owner)
                        .arg("NX")
                        .arg("EX")
                        .arg(LEASE_TTL_SECS)
                        .query_async::<Option<String>>(&mut connection)
                        .await
                })
                .await
                .map_err(|_| {
                    warn!(%user_id, "Redis rule-test admission request timed out");
                    RuleTestAdmissionError::Unavailable
                })?
                .map_err(|error| {
                    warn!(%user_id, %error, "Redis rule-test admission request failed");
                    RuleTestAdmissionError::Unavailable
                })?;

                if result.is_none() {
                    return Ok(None);
                }

                let renewal = spawn_renewal(connection.clone(), key.clone(), owner.clone());
                Ok(Some(RuleTestPermit {
                    release: Some(PermitRelease::Redis {
                        connection,
                        key,
                        owner,
                        renewal,
                    }),
                }))
            }
        }
    }
}

impl RedisBackend {
    async fn connection(&self) -> Result<ConnectionManager, RuleTestAdmissionError> {
        let mut stored = self.connection.lock().await;
        if let Some(connection) = stored.as_ref() {
            return Ok(connection.clone());
        }

        let client = redis::Client::open(self.redis_url.as_str()).map_err(|error| {
            warn!(%error, "Invalid Redis configuration for rule-test admission");
            RuleTestAdmissionError::Unavailable
        })?;
        let connection =
            tokio::time::timeout(REDIS_OPERATION_TIMEOUT, ConnectionManager::new(client))
                .await
                .map_err(|_| {
                    warn!("Redis rule-test admission connection timed out");
                    RuleTestAdmissionError::Unavailable
                })?
                .map_err(|error| {
                    warn!(%error, "Redis rule-test admission connection failed");
                    RuleTestAdmissionError::Unavailable
                })?;
        *stored = Some(connection.clone());
        Ok(connection)
    }
}

fn spawn_renewal(mut connection: ConnectionManager, key: String, owner: String) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(RENEW_INTERVAL_SECS));
        interval.tick().await;
        loop {
            interval.tick().await;
            let renewed = tokio::time::timeout(REDIS_OPERATION_TIMEOUT, async {
                redis::Script::new(RENEW_IF_OWNER_SCRIPT)
                    .key(&key)
                    .arg(&owner)
                    .arg(LEASE_TTL_SECS)
                    .invoke_async::<i32>(&mut connection)
                    .await
            })
            .await;
            match renewed {
                Ok(Ok(1)) => {}
                Ok(Ok(_)) => {
                    warn!(%key, "Rule-test admission lease ownership was lost");
                    break;
                }
                Ok(Err(error)) => {
                    warn!(%key, %error, "Failed to renew rule-test admission lease");
                }
                Err(_) => warn!(%key, "Rule-test admission lease renewal timed out"),
            }
        }
    })
}

enum PermitRelease {
    Local {
        active: Arc<DashMap<Uuid, ()>>,
        user_id: Uuid,
    },
    Redis {
        connection: ConnectionManager,
        key: String,
        owner: String,
        renewal: JoinHandle<()>,
    },
}

/// RAII lease. Cancellation and early returns release the local slot; Redis
/// release is owner-checked and the TTL covers process crashes.
pub struct RuleTestPermit {
    release: Option<PermitRelease>,
}

impl Drop for RuleTestPermit {
    fn drop(&mut self) {
        let Some(release) = self.release.take() else {
            return;
        };
        match release {
            PermitRelease::Local { active, user_id } => {
                active.remove(&user_id);
            }
            PermitRelease::Redis {
                mut connection,
                key,
                owner,
                renewal,
            } => {
                renewal.abort();
                tokio::spawn(async move {
                    let released = tokio::time::timeout(REDIS_OPERATION_TIMEOUT, async {
                        redis::Script::new(RELEASE_IF_OWNER_SCRIPT)
                            .key(&key)
                            .arg(&owner)
                            .invoke_async::<i32>(&mut connection)
                            .await
                    })
                    .await;
                    match released {
                        Ok(Ok(1)) => debug!(%key, "Released distributed rule-test admission"),
                        Ok(Ok(_)) => debug!(%key, "Rule-test admission was no longer owned"),
                        Ok(Err(error)) => {
                            warn!(%key, %error, "Failed to release rule-test admission lease")
                        }
                        Err(_) => warn!(%key, "Rule-test admission release timed out"),
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_admission_is_exclusive_and_releases_on_drop() {
        let admission = RuleTestAdmission::local();
        let user_id = Uuid::now_v7();
        let permit = admission.acquire(user_id).await.unwrap().unwrap();
        assert!(admission.acquire(user_id).await.unwrap().is_none());
        drop(permit);
        assert!(admission.acquire(user_id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn local_admission_is_scoped_per_user() {
        let admission = RuleTestAdmission::local();
        let first = admission.acquire(Uuid::now_v7()).await.unwrap();
        let second = admission.acquire(Uuid::now_v7()).await.unwrap();
        assert!(first.is_some());
        assert!(second.is_some());
    }

    #[tokio::test]
    async fn configured_invalid_redis_fails_closed_without_disclosing_the_url() {
        let secret_url = "not-a-redis-url-with-secret";
        let admission = RuleTestAdmission::try_with_redis_url(secret_url).await;
        let error = match admission.acquire(Uuid::now_v7()).await {
            Err(error) => error,
            Ok(_) => panic!("an invalid configured backend must fail closed"),
        };
        assert!(!error.to_string().contains(secret_url));
    }

    #[test]
    fn redis_scripts_are_owner_fenced() {
        assert!(RENEW_IF_OWNER_SCRIPT.contains("GET"));
        assert!(RENEW_IF_OWNER_SCRIPT.contains("EXPIRE"));
        assert!(RELEASE_IF_OWNER_SCRIPT.contains("GET"));
        assert!(RELEASE_IF_OWNER_SCRIPT.contains("DEL"));
    }

    #[tokio::test]
    #[ignore = "requires REDIS_URL"]
    async fn independent_instances_share_one_user_lease() {
        let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL");
        let first = RuleTestAdmission::try_with_redis_url(&redis_url).await;
        let second = RuleTestAdmission::try_with_redis_url(&redis_url).await;
        let user_id = Uuid::now_v7();

        let permit = first.acquire(user_id).await.unwrap().unwrap();
        assert!(second.acquire(user_id).await.unwrap().is_none());
        drop(permit);

        let mut reclaimed = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(25)).await;
            if second.acquire(user_id).await.unwrap().is_some() {
                reclaimed = true;
                break;
            }
        }
        assert!(
            reclaimed,
            "owner-fenced release should make the slot reusable"
        );
    }
}
