// SPDX-License-Identifier: AGPL-3.0-or-later

//! Boot-time descriptor budget shared by all lake-worker executables.
use anyhow::{Result, bail};
use std::sync::OnceLock;

const DEFAULT_SOFT: u64 = 65_536;
const MIN_HARD: u64 = 4_096;

/// Run before argument parsing, credentials, or network clients. Emit directly
/// to stderr because several maintenance binaries have no tracing subscriber.
/// The OnceLock ensures one boot record even if an embedding calls us twice.
pub fn initialize() -> Result<()> {
    static INITIALIZED: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    INITIALIZED
        .get_or_init(|| {
            let requested = match std::env::var("NANO_LAKE_NOFILE_SOFT") {
                Ok(value) => parse_soft(&value).unwrap_or_else(|| {
                    eprintln!("invalid NANO_LAKE_NOFILE_SOFT; using 65536");
                    DEFAULT_SOFT
                }),
                Err(_) => DEFAULT_SOFT,
            };
            if let Some((old_soft, hard, new_soft)) =
                raise_nofile(requested).map_err(|e| e.to_string())?
            {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "event": "lake_nofile_limit", "old_soft": old_soft,
                        "hard": hard, "new_soft": new_soft,
                    })
                );
            }
            // Initializes the shared instrumented transport before any FileIO.
            crate::r2_ops::install_iceberg_http_client();
            let _ = iceberg_storage_opendal::manifest_fetch::concurrency();
            Ok(())
        })
        .clone()
        .map_err(anyhow::Error::msg)
}

fn parse_soft(value: &str) -> Option<u64> {
    value.parse().ok().filter(|n| *n > 0)
}

fn raise_nofile(requested: u64) -> Result<Option<(u64, u64, u64)>> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limit points to a valid writable rlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        eprintln!(
            "unable to read RLIMIT_NOFILE: {}",
            std::io::Error::last_os_error()
        );
        return Ok(None);
    }
    let old_soft = limit.rlim_cur as u64;
    let hard = limit.rlim_max as u64;
    if hard < MIN_HARD {
        bail!("RLIMIT_NOFILE hard limit {hard} is below required {MIN_HARD}");
    }
    // Never reduce an already higher inherited soft limit or change the hard
    // limit. Explicit overrides are capped by the inherited hard limit.
    let new_soft = old_soft.max(requested.min(hard));
    limit.rlim_cur = new_soft as libc::rlim_t;
    if new_soft != old_soft {
        // SAFETY: limit is initialized and its hard limit is unchanged.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
            eprintln!(
                "unable to raise RLIMIT_NOFILE: {}",
                std::io::Error::last_os_error()
            );
            return Ok(Some((old_soft, hard, old_soft)));
        }
    }
    Ok(Some((old_soft, hard, new_soft)))
}

/// A process-wide observation window; overlapping cycles include shared
/// process activity. Drop logs on success, early return, failure or cancellation.
pub struct ManifestCycle {
    operation: &'static str,
    started: std::time::Instant,
    observation: iceberg_storage_opendal::manifest_fetch::Observation,
}
impl ManifestCycle {
    pub fn start(operation: &'static str) -> Self {
        Self {
            operation,
            started: std::time::Instant::now(),
            observation: iceberg_storage_opendal::manifest_fetch::Observation::start(),
        }
    }
}
impl Drop for ManifestCycle {
    fn drop(&mut self) {
        let counts = self.observation.snapshot();
        eprintln!(
            "{}",
            serde_json::json!({
                "event": "lake_manifest_cycle", "operation": self.operation,
                "scope": "process_during_cycle", "manifests_fetched": counts.manifests_fetched,
                "max_concurrent": counts.max_concurrent, "retries": counts.retries,
                "cycle_duration_ms": self.started.elapsed().as_millis(),
                "concurrency_limit": iceberg_storage_opendal::manifest_fetch::concurrency(),
            })
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn soft_configuration() {
        assert_eq!(parse_soft("8192"), Some(8192));
        for value in ["0", "-1", "invalid", ""] {
            assert_eq!(parse_soft(value), None);
        }
    }
    #[test]
    fn raises_lowered_soft_limit_in_process() {
        const CHILD: &str = "NAN2498_RLIMIT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "process_limits::tests::raises_lowered_soft_limit_in_process",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let mut original = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original) },
            0
        );
        let lowered = libc::rlimit {
            rlim_cur: 256,
            rlim_max: original.rlim_max,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) }, 0);
        let (old, hard, new) = raise_nofile(65_536).unwrap().unwrap();
        let mut actual = lowered;
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut actual) },
            0
        );
        assert_eq!(old, 256);
        assert_eq!(hard, original.rlim_max as u64);
        assert_eq!(new, hard.min(65_536));
        assert_eq!(actual.rlim_cur as u64, new);
        assert_eq!(actual.rlim_max, original.rlim_max);
        // Overrides and a constrained hard limit, still inside this child.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) }, 0);
        assert_eq!(raise_nofile(8192).unwrap().unwrap().2, 8192);
        assert_eq!(raise_nofile(4096).unwrap().unwrap().2, 8192); // never lower
        let capped = libc::rlimit {
            rlim_cur: 256,
            rlim_max: 4096,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &capped) }, 0);
        assert_eq!(raise_nofile(65_536).unwrap().unwrap(), (256, 4096, 4096));
        let insufficient = libc::rlimit {
            rlim_cur: 256,
            rlim_max: 2048,
        };
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &insufficient) },
            0
        );
        assert!(
            raise_nofile(65_536)
                .unwrap_err()
                .to_string()
                .contains("below required 4096")
        );
    }
}
