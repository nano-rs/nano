// SPDX-License-Identifier: AGPL-3.0-or-later

//! Periodic glibc `malloc_trim(0)` for long-lived services.
//!
//! A burst of large `serde_json::Value` trees (a lake result page, a rule
//! window) is freed back to glibc's arenas but not to the kernel, so the
//! cgroup keeps charging the peak as anonymous memory and the next burst
//! stacks on top of it. Trimming on a timer returns those free pages; live
//! allocations are untouched, so a real leak stays visible.

use std::time::Duration;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn malloc_trim(pad: usize) -> std::ffi::c_int;
}

/// `VmRSS` from a `/proc/<pid>/status` body, in bytes.
pub fn parse_process_rss_bytes(status: &str) -> Option<u64> {
    let kibibytes = status.lines().find_map(|line| {
        line.strip_prefix("VmRSS:")?
            .split_ascii_whitespace()
            .next()?
            .parse::<u64>()
            .ok()
    })?;
    kibibytes.checked_mul(1024)
}

fn process_rss_bytes() -> Option<u64> {
    parse_process_rss_bytes(&std::fs::read_to_string("/proc/self/status").ok()?)
}

/// Trim when RSS is at least `minimum_rss_bytes`: `(before, after, trimmed)`.
fn trim_if_needed(minimum_rss_bytes: u64) -> (Option<u64>, Option<u64>, bool) {
    let before = process_rss_bytes();
    if before.is_none_or(|rss| rss < minimum_rss_bytes) {
        return (before, before, false);
    }
    #[cfg(target_os = "linux")]
    let trimmed = {
        // SAFETY: glibc documents malloc_trim(0) as a process-wide, thread-safe
        // request to release unused allocator pages. Live allocations are
        // untouched, so a real leak remains visible.
        (unsafe { malloc_trim(0) }) != 0
    };
    #[cfg(not(target_os = "linux"))]
    let trimmed = false;
    (before, process_rss_bytes(), trimmed)
}

/// Trim every `interval` while RSS is at least `minimum_rss_bytes`, until
/// `shutdown` fires.
pub async fn run_allocator_trim_loop(
    service: &'static str,
    interval: Duration,
    minimum_rss_bytes: u64,
    shutdown: crate::shutdown::ShutdownToken,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = ticker.tick() => {
                match tokio::task::spawn_blocking(move || trim_if_needed(minimum_rss_bytes)).await {
                    Ok((Some(before), Some(after), true)) if after < before => tracing::info!(
                        service,
                        rss_before_bytes = before,
                        rss_after_bytes = after,
                        released_bytes = before - after,
                        "released unused host-allocator pages"
                    ),
                    Ok((before, after, true)) => tracing::debug!(
                        service,
                        rss_before_bytes = before,
                        rss_after_bytes = after,
                        "host allocator had no releasable RSS"
                    ),
                    Ok(_) => {}
                    Err(error) => tracing::warn!(service, ?error, "allocator trim task failed"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_process_rss_without_confusing_virtual_memory() {
        let status = "Name:\tnanosiem-search\nVmSize:\t999999 kB\nVmRSS:\t  12345 kB\n";
        assert_eq!(parse_process_rss_bytes(status), Some(12_641_280));
        assert_eq!(parse_process_rss_bytes("VmSize:\t123 kB\n"), None);
    }

    #[test]
    fn below_the_threshold_nothing_is_trimmed() {
        let (before, after, trimmed) = trim_if_needed(u64::MAX);
        assert!(!trimmed);
        assert_eq!(before, after);
    }
}
