//! Profile data loading — real telemetry data compiled into the binary
//!
//! Profile files are loaded via `include_str!` at compile time (~625K total).
//! Parsed once at startup into typed structs with weighted sampling.

use rand::distr::{weighted::WeightedIndex, Distribution};
use rand::Rng;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::OnceLock;

static PROFILES: OnceLock<ProfileData> = OnceLock::new();

const PROCESS_CHAINS_JSON: &str = include_str!("../profiles/process_tree_chains.json");
const FILE_HASHES_JSON: &str = include_str!("../profiles/file_hash_chains.json");
const PROXY_PATTERNS_JSON: &str = include_str!("../profiles/proxy_traffic_patterns.json");
const SYSMON_DIST_JSON: &str = include_str!("../profiles/sysmon_event_distribution.json");

/// Get the global profile data instance
pub fn profiles() -> &'static ProfileData {
    PROFILES.get_or_init(ProfileData::load)
}

/// A real process parent-child chain from the lab
#[derive(Debug, Clone, Deserialize)]
pub struct ProcessChain {
    pub process_name: String,
    pub process_path: String,
    pub process_hash: String,
    pub parent_process_name: String,
    pub parent_process_path: String,
    pub parent_command_line: String,
    pub command_line: String,
    pub cnt: u64,
}

/// A real file hash relationship from the lab
#[derive(Debug, Clone, Deserialize)]
pub struct FileHashEntry {
    pub file_path: String,
    pub file_name: String,
    pub file_hash: String,
    pub file_action: String,
    pub process_name: String,
    pub process_path: String,
    pub user: String,
    pub cnt: u64,
}

/// A real proxy traffic pattern from the lab
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyPattern {
    pub src_ip: String,
    pub dest_ip: String,
    pub src_host: String,
    pub dest_host: String,
    pub user: String,
    pub src_port: u16,
    pub dest_port: u16,
    pub protocol: String,
    pub url_domain: String,
    pub http_method: String,
    pub http_status_code: u16,
    pub http_user_agent: String,
    pub cnt: u64,
}

/// Sysmon event type distribution from the lab
#[derive(Debug, Clone, Deserialize)]
pub struct SysmonEventDist {
    pub signature_id: String,
    pub action: String,
    pub category: String,
    pub cnt: u64,
    pub unique_hosts: u64,
    pub unique_users: u64,
    pub unique_processes: u64,
}

/// Loaded and indexed profile data
pub struct ProfileData {
    pub process_chains: Vec<ProcessChain>,
    pub file_hashes: Vec<FileHashEntry>,
    pub proxy_patterns: Vec<ProxyPattern>,
    pub sysmon_dist: Vec<SysmonEventDist>,
    /// Weighted index for sampling process chains by frequency
    chain_weights: WeightedIndex<f64>,
    /// Weighted index for sampling file hash entries
    file_weights: WeightedIndex<f64>,
    /// Weighted index for sampling proxy patterns
    proxy_weights: WeightedIndex<f64>,
    /// Weighted index for sampling sysmon event types
    sysmon_weights: WeightedIndex<f64>,
}

/// Paths that indicate Ludus lab artifacts — not real enterprise telemetry
const LAB_PATH_PREFIXES: &[&str] = &[r"C:\ludus\", r"c:\ludus\"];

/// Cap weights at the 95th percentile to prevent any single entry from dominating
fn capped_weights(counts: &[u64]) -> Vec<f64> {
    if counts.is_empty() {
        return vec![];
    }
    let mut sorted: Vec<u64> = counts.to_vec();
    sorted.sort_unstable();
    let p95_idx = (sorted.len() as f64 * 0.95) as usize;
    let cap = sorted[p95_idx.min(sorted.len() - 1)].max(1);
    counts.iter().map(|&c| c.min(cap).max(1) as f64).collect()
}

impl ProfileData {
    fn load() -> Self {
        let process_chains: Vec<ProcessChain> = PROCESS_CHAINS_JSON
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<ProcessChain>(l).ok())
            .filter(|c| {
                !LAB_PATH_PREFIXES
                    .iter()
                    .any(|p| c.process_path.starts_with(p))
            })
            .collect();

        let file_hashes: Vec<FileHashEntry> = FILE_HASHES_JSON
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<FileHashEntry>(l).ok())
            .filter(|f| !LAB_PATH_PREFIXES.iter().any(|p| f.file_path.starts_with(p)))
            .collect();

        let proxy_patterns: Vec<ProxyPattern> = PROXY_PATTERNS_JSON
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();

        let sysmon_dist: Vec<SysmonEventDist> = SYSMON_DIST_JSON
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();

        let chain_weights = WeightedIndex::new(capped_weights(
            &process_chains.iter().map(|c| c.cnt).collect::<Vec<_>>(),
        ))
        .expect("process_chains must not be empty (after filtering lab artifacts)");

        let file_weights = WeightedIndex::new(capped_weights(
            &file_hashes.iter().map(|f| f.cnt).collect::<Vec<_>>(),
        ))
        .expect("file_hashes must not be empty");

        let proxy_weights = WeightedIndex::new(
            proxy_patterns
                .iter()
                .map(|p| p.cnt.max(1) as f64)
                .collect::<Vec<_>>(),
        )
        .expect("proxy_patterns must not be empty");

        let sysmon_weights =
            WeightedIndex::new(sysmon_dist.iter().map(|s| s.cnt as f64).collect::<Vec<_>>())
                .expect("sysmon_dist must not be empty");

        tracing::info!(
            "Loaded profiles: {} process chains, {} file hashes, {} proxy patterns, {} sysmon event types",
            process_chains.len(), file_hashes.len(), proxy_patterns.len(), sysmon_dist.len()
        );

        Self {
            process_chains,
            file_hashes,
            proxy_patterns,
            sysmon_dist,
            chain_weights,
            file_weights,
            proxy_weights,
            sysmon_weights,
        }
    }

    /// Sample a random process chain weighted by frequency
    pub fn sample_process_chain(&self, rng: &mut impl Rng) -> &ProcessChain {
        &self.process_chains[self.chain_weights.sample(rng)]
    }

    /// Most frequently observed hash for this exact executable in the normal
    /// telemetry profile. Scripted campaigns use this to keep signed wrappers
    /// and LOLBins on the same prevalence identity as background log-blaster
    /// traffic. If the profile has never observed the executable, callers
    /// should omit the hash rather than inventing a new low-prevalence value.
    pub fn process_hash_for(&self, path: &str, name: &str) -> Option<&str> {
        most_prevalent_process_hash(self.process_chains.iter(), path, name)
    }

    /// Sample a random file hash entry weighted by frequency
    pub fn sample_file_hash(&self, rng: &mut impl Rng) -> &FileHashEntry {
        &self.file_hashes[self.file_weights.sample(rng)]
    }

    /// Sample a random proxy pattern weighted by frequency
    pub fn sample_proxy_pattern(&self, rng: &mut impl Rng) -> &ProxyPattern {
        &self.proxy_patterns[self.proxy_weights.sample(rng)]
    }

    /// Sample a random sysmon event type weighted by real distribution
    pub fn sample_sysmon_event(&self, rng: &mut impl Rng) -> &SysmonEventDist {
        &self.sysmon_dist[self.sysmon_weights.sample(rng)]
    }
}

fn most_prevalent_process_hash<'a>(
    chains: impl Iterator<Item = &'a ProcessChain>,
    path: &str,
    name: &str,
) -> Option<&'a str> {
    let mut counts = BTreeMap::<&str, u64>::new();
    for chain in chains.filter(|chain| {
        chain.process_path.eq_ignore_ascii_case(path)
            && chain.process_name.eq_ignore_ascii_case(name)
            && chain.process_hash.len() == 64
            && chain
                .process_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
    }) {
        *counts.entry(&chain.process_hash).or_default() += chain.cnt;
    }
    counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(hash, _)| hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(hash: &str, count: u64) -> ProcessChain {
        ProcessChain {
            process_name: "tool.exe".into(),
            process_path: r"C:\Windows\tool.exe".into(),
            process_hash: hash.into(),
            parent_process_name: String::new(),
            parent_process_path: String::new(),
            parent_command_line: String::new(),
            command_line: String::new(),
            cnt: count,
        }
    }

    #[test]
    fn process_hash_prevalence_is_aggregated_across_profile_rows() {
        const HASH_A: &str =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const HASH_B: &str =
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let chains = [chain(HASH_A, 4), chain(HASH_A, 4), chain(HASH_B, 7)];

        assert_eq!(
            most_prevalent_process_hash(chains.iter(), r"C:\Windows\tool.exe", "tool.exe"),
            Some(HASH_A)
        );
    }
}
