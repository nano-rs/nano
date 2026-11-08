// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pre-emission normalizer check for identity pulls (NAN-3483).
//!
//! The `nano_enrich` lane is asynchronous after its durable disk handoff: a record the lane's
//! `enrichment_normalize_<source>` transform aborts on is dead-lettered inside
//! Vector and the sync never hears about it. On open core that let an Okta
//! sync report `completed` while every record was dropped.
//!
//! The gate runs the same normalizer the lane runs (the imported, enabled
//! parser for the source, else the built-in one) over each record as it is
//! emitted, and counts the ones the lane will dead-letter with the first
//! reason. It does not filter: every record still traverses Vector, which
//! does the real normalizing. The sync status is derived from the counts by
//! [`verdict`].

use crate::parsers::CompiledNormalizer;

/// Where a gate's normalizer came from, for status messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizerOrigin {
    /// An imported, enabled enrichment parser (by name).
    Imported(String),
    /// The built-in normalizer compiled into the binary.
    Builtin,
}

impl std::fmt::Display for NormalizerOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Imported(name) => write!(f, "imported parser {name}"),
            Self::Builtin => f.write_str("built-in"),
        }
    }
}

/// Runs one source's normalizer over records before they are emitted.
#[derive(Debug)]
pub struct IdentityRecordGate {
    transform: String,
    origin: NormalizerOrigin,
    normalizer: CompiledNormalizer,
}

impl IdentityRecordGate {
    /// Compile `normalize_vrl` for `source`. An error names the source so a
    /// broken normalizer fails the sync loudly instead of dead-lettering
    /// every record.
    pub fn new(
        source: &str,
        origin: NormalizerOrigin,
        normalize_vrl: &str,
    ) -> Result<Self, String> {
        let normalizer = CompiledNormalizer::compile(normalize_vrl).map_err(|e| {
            format!("identity normalizer for source '{source}' ({origin}) does not compile: {e}")
        })?;
        Ok(Self {
            transform: format!("enrichment_normalize_{source}"),
            origin,
            normalizer,
        })
    }

    /// The lane transform this gate mirrors (`enrichment_normalize_<source>`).
    pub fn transform(&self) -> &str {
        &self.transform
    }

    pub fn origin(&self) -> &NormalizerOrigin {
        &self.origin
    }

    /// Count, in `tally`, how many of `records` the lane's normalizer will
    /// dead-letter, and remember the first reason. Records are NOT filtered:
    /// every record still goes through Vector, the ingest path, which does
    /// the real normalizing and dead-lettering; this only predicts it so the
    /// sync status is honest. Records must already carry the lane tags
    /// (`kind`/`source`/`provider_id`) the normalizer reads.
    pub fn tally(&self, records: &[serde_json::Value], tally: &mut SyncTally) {
        for record in records {
            tally.total += 1;
            if self.normalizer.accepts(record) {
                continue;
            }
            tally.dead_lettered += 1;
            // Only the first rejection pays for the explained re-run.
            if tally.first_reason.is_none() {
                tally.first_reason = self.normalizer.run(record).err();
            }
        }
    }
}

/// Record counts of one sync.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncTally {
    /// Records fetched from the provider.
    pub total: u64,
    /// Records the lane's normalizer will dead-letter.
    pub dead_lettered: u64,
    /// Why the first rejected record was rejected.
    pub first_reason: Option<String>,
}

impl SyncTally {
    /// Records the lane's normalizer will map into the directory.
    pub fn synced(&self) -> u64 {
        self.total.saturating_sub(self.dead_lettered)
    }
}

/// The status a finished sync is recorded with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncVerdict {
    /// Every record was emitted (or the directory is empty).
    Completed,
    /// Some records were dead-lettered; the message says how many and why.
    Partial(String),
    /// Every record was dead-lettered.
    Failed(String),
}

impl SyncVerdict {
    pub fn status(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Partial(_) => "partial",
            Self::Failed(_) => "failed",
        }
    }

    pub fn error(&self) -> Option<&str> {
        match self {
            Self::Completed => None,
            Self::Partial(m) | Self::Failed(m) => Some(m),
        }
    }
}

/// Derive the sync status from its counts: any dead-lettered record makes it
/// `partial`; all of them make it `failed`.
pub fn verdict(tally: &SyncTally, gate: &IdentityRecordGate) -> SyncVerdict {
    if tally.dead_lettered == 0 {
        return SyncVerdict::Completed;
    }
    let reason = tally.first_reason.as_deref().unwrap_or("unknown reason");
    let by = format!("{} ({})", gate.transform(), gate.origin());
    if tally.dead_lettered >= tally.total {
        SyncVerdict::Failed(format!(
            "all {} records dead-lettered by {by}; first reason: {reason}",
            tally.total
        ))
    } else {
        SyncVerdict::Partial(format!(
            "{} of {} records dead-lettered by {by}; first reason: {reason}",
            tally.dead_lettered, tally.total
        ))
    }
}

#[cfg(test)]
#[path = "gate_tests.rs"]
mod tests;
