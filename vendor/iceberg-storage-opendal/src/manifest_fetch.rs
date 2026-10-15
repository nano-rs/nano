//! NAN-2498: process-wide admission for Iceberg Avro reads, including reads
//! spawned internally by transaction duplicate validation and scan planning.
use std::sync::{
    Arc, Mutex, OnceLock, Weak,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use tokio::sync::{Semaphore, SemaphorePermit};

pub const DEFAULT_CONCURRENCY: usize = 64;
static LIMIT: OnceLock<Semaphore> = OnceLock::new();
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static OBSERVERS: Mutex<Vec<Weak<Counters>>> = Mutex::new(Vec::new());

/// Read once per process. Invalid/zero/excessive values fall back to 64.
pub fn concurrency() -> usize {
    static CONFIG: OnceLock<usize> = OnceLock::new();
    *CONFIG.get_or_init(
        || match std::env::var("NANO_LAKE_MANIFEST_FETCH_CONCURRENCY") {
            Ok(value) => parse_concurrency(&value).unwrap_or_else(|| {
                eprintln!("invalid NANO_LAKE_MANIFEST_FETCH_CONCURRENCY; using 64");
                DEFAULT_CONCURRENCY
            }),
            Err(_) => DEFAULT_CONCURRENCY,
        },
    )
}
fn parse_concurrency(value: &str) -> Option<usize> {
    value.parse().ok().filter(|n| (1..=65_536).contains(n))
}
pub(crate) fn is_manifest(path: &str) -> bool {
    path.ends_with(".avro")
}

#[derive(Default)]
struct Counters {
    fetched: AtomicU64,
    retries: AtomicU64,
    peak: AtomicUsize,
}
/// Process activity during one cycle's lifetime. Overlapping cycles explicitly
/// observe the same process activity; these are not tenant accounting counters.
pub struct Observation(Arc<Counters>);
#[derive(Debug, Default)]
pub struct Snapshot {
    pub manifests_fetched: u64,
    pub retries: u64,
    pub max_concurrent: usize,
}
impl Observation {
    pub fn start() -> Self {
        let counters = Arc::new(Counters::default());
        let mut observers = OBSERVERS.lock().unwrap_or_else(|e| e.into_inner());
        counters
            .peak
            .store(ACTIVE.load(Ordering::SeqCst), Ordering::Relaxed);
        observers.retain(|observer| observer.strong_count() != 0);
        observers.push(Arc::downgrade(&counters));
        Self(counters)
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            manifests_fetched: self.0.fetched.load(Ordering::Relaxed),
            retries: self.0.retries.load(Ordering::Relaxed),
            max_concurrent: self.0.peak.load(Ordering::Relaxed),
        }
    }
}
fn observe(f: impl Fn(&Counters)) {
    let mut observers = OBSERVERS.lock().unwrap_or_else(|e| e.into_inner());
    observers.retain(|observer| {
        if let Some(counters) = observer.upgrade() {
            f(&counters);
            true
        } else {
            false
        }
    });
}
pub(crate) fn retry() {
    observe(|c| {
        c.retries.fetch_add(1, Ordering::Relaxed);
    });
}

pub(crate) struct Permit {
    _permit: SemaphorePermit<'static>,
}
impl Permit {
    pub(crate) fn fetched(&self) {
        observe(|c| {
            c.fetched.fetch_add(1, Ordering::Relaxed);
        });
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::SeqCst);
    }
}
pub(crate) async fn acquire(path_is_manifest: bool) -> Option<Permit> {
    if !path_is_manifest {
        return None;
    }
    // Keep the permit through body consumption and all OpenDAL retries. RAII
    // releases on success, error and cancellation; no locks cross an await.
    let permit = LIMIT
        .get_or_init(|| Semaphore::new(concurrency()))
        .acquire()
        .await
        .expect("private semaphore is never closed");
    let active = ACTIVE.fetch_add(1, Ordering::SeqCst) + 1;
    observe(|c| {
        c.peak.fetch_max(active, Ordering::Relaxed);
    });
    Some(Permit { _permit: permit })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrency_configuration() {
        assert_eq!(parse_concurrency("64"), Some(64));
        assert_eq!(parse_concurrency("1"), Some(1));
        for value in ["0", "-1", "wat", "65537", ""] {
            assert_eq!(parse_concurrency(value), None);
        }
        assert!(is_manifest("s3://bucket/metadata/snap-1.avro"));
        assert!(is_manifest("s3://bucket/metadata/id-m0.avro"));
        assert!(!is_manifest("s3://bucket/data/a.parquet"));
    }
    #[tokio::test]
    async fn cancellation_releases_admission() {
        let observation = Observation::start();
        let mut permits = Vec::new();
        for _ in 0..concurrency() {
            permits.push(acquire(true).await.unwrap());
        }
        let waiting = acquire(true);
        tokio::pin!(waiting);
        assert!(futures::poll!(&mut waiting).is_pending());
        let mut cancelled_waiter = Box::pin(acquire(true));
        assert!(futures::poll!(&mut cancelled_waiter).is_pending());
        drop(cancelled_waiter);
        drop(permits.pop());
        let admitted = waiting.await.unwrap();
        admitted.fetched();
        retry();
        assert_eq!(observation.snapshot().manifests_fetched, 1);
        assert_eq!(observation.snapshot().retries, 1);
        assert_eq!(observation.snapshot().max_concurrent, concurrency());
        drop(admitted);
        drop(permits);
        assert_eq!(ACTIVE.load(Ordering::SeqCst), 0);
        assert_eq!(LIMIT.get().unwrap().available_permits(), concurrency());
        // Cancel an admitted future while it holds its permit (as a body
        // read would), then cancel a waiter before admission.
        let mut cancelled = Box::pin(async {
            let _permit = acquire(true).await.unwrap();
            futures::future::pending::<()>().await;
        });
        assert!(futures::poll!(&mut cancelled).is_pending());
        assert_eq!(ACTIVE.load(Ordering::SeqCst), 1);
        drop(cancelled);
        assert_eq!(ACTIVE.load(Ordering::SeqCst), 0);
        assert_eq!(LIMIT.get().unwrap().available_permits(), concurrency());
        assert!(acquire(false).await.is_none());
    }
}
