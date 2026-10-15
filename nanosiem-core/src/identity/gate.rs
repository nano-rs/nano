// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pre-emission normalizer check for identity pulls (NAN-3483).
//!
//! The `nano_enrich` lane is fire-and-forget: a record the lane's
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
mod tests {
    use super::*;
    use crate::identity::normalizers::builtin_identity_normalizer;
    use serde_json::json;

    fn tagged(mut user: serde_json::Value, source: &str) -> serde_json::Value {
        user["kind"] = json!("identity");
        user["source"] = json!(source);
        user["provider_id"] = json!("okta-test");
        user
    }

    fn okta_user(id: &str) -> serde_json::Value {
        json!({
            "id": id, "status": "ACTIVE",
            "profile": {"login": format!("{id}@example.com"), "email": format!("{id}@example.com"),
                        "firstName": "Test", "lastName": "User"}
        })
    }

    fn builtin_gate(source: &str) -> IdentityRecordGate {
        let b = builtin_identity_normalizer(source).unwrap();
        IdentityRecordGate::new(source, NormalizerOrigin::Builtin, b.normalize_vrl).unwrap()
    }

    #[test]
    fn every_builtin_compiles_into_a_gate() {
        for b in crate::identity::normalizers::BUILTIN_IDENTITY_NORMALIZERS {
            IdentityRecordGate::new(b.source, NormalizerOrigin::Builtin, b.normalize_vrl)
                .unwrap_or_else(|e| panic!("{}: {e}", b.source));
        }
    }

    #[test]
    fn every_builtin_passes_the_user_registry_contract() {
        for b in crate::identity::normalizers::BUILTIN_IDENTITY_NORMALIZERS {
            crate::parsers::validate_enrichment_encoding_contract("identity", b.normalize_vrl)
                .unwrap_or_else(|e| panic!("{}: {e}", b.source));
        }
    }

    #[test]
    fn okta_records_pass_the_okta_normalizer() {
        let gate = builtin_gate("okta");
        let mut tally = SyncTally::default();
        let records = vec![
            tagged(okta_user("00u1"), "okta"),
            tagged(okta_user("00u2"), "okta"),
        ];
        gate.tally(&records, &mut tally);
        assert_eq!(
            tally,
            SyncTally {
                total: 2,
                dead_lettered: 0,
                first_reason: None
            }
        );
        assert_eq!(verdict(&tally, &gate), SyncVerdict::Completed);
    }

    /// The CT106 failure: Okta records through the AD normalizer. Every one
    /// is rejected, and the verdict is `failed` with the VRL's own reason.
    #[test]
    fn okta_records_through_the_ad_normalizer_all_dead_letter() {
        let gate = builtin_gate("ad");
        let mut tally = SyncTally::default();
        let records: Vec<_> = (0..3)
            .map(|i| tagged(okta_user(&format!("00u{i}")), "okta"))
            .collect();
        gate.tally(&records, &mut tally);
        assert_eq!(tally.total, 3);
        assert_eq!(tally.dead_lettered, 3);
        let reason = tally.first_reason.clone().unwrap();
        assert!(reason.contains("missing external_id"), "reason: {reason}");
        match verdict(&tally, &gate) {
            SyncVerdict::Failed(m) => {
                assert!(m.contains("all 3 records"), "{m}");
                assert!(m.contains("enrichment_normalize_ad (built-in)"), "{m}");
                assert!(m.contains("missing external_id"), "{m}");
            }
            other => panic!("expected failed, got {other:?}"),
        }
    }

    #[test]
    fn some_dead_lettered_is_partial_with_counts() {
        let gate = builtin_gate("okta");
        let mut tally = SyncTally::default();
        let records = vec![
            tagged(okta_user("00u1"), "okta"),
            tagged(json!({"status": "ACTIVE", "profile": {}}), "okta"),
            tagged(okta_user("00u3"), "okta"),
        ];
        gate.tally(&records, &mut tally);
        assert_eq!(tally.synced(), 2);
        let v = verdict(&tally, &gate);
        assert_eq!(v.status(), "partial");
        let m = v.error().unwrap();
        assert!(
            m.starts_with("1 of 3 records dead-lettered by enrichment_normalize_okta"),
            "{m}"
        );
        assert!(m.contains("missing id"), "{m}");
    }

    /// NAN-3483 status alignment: Okta SUSPENDED stays `suspended`.
    #[test]
    fn okta_suspended_maps_to_suspended() {
        let b = builtin_identity_normalizer("okta").unwrap();
        let program = crate::parsers::CompiledNormalizer::compile(b.normalize_vrl).unwrap();
        let mut user = tagged(okta_user("00u9"), "okta");
        user["status"] = json!("SUSPENDED");
        let out = program.run(&user).unwrap();
        assert_eq!(out["account_status"], "suspended");
        assert_eq!(out["account_enabled"], 0);
        user["status"] = json!("DEPROVISIONED");
        assert_eq!(program.run(&user).unwrap()["account_status"], "disabled");
    }

    #[test]
    fn empty_directory_is_completed() {
        let gate = builtin_gate("okta");
        assert_eq!(
            verdict(&SyncTally::default(), &gate),
            SyncVerdict::Completed
        );
    }

    #[test]
    fn a_normalizer_that_does_not_compile_fails_loudly() {
        let err = IdentityRecordGate::new(
            "okta",
            NormalizerOrigin::Imported("okta_identity".into()),
            "this is not vrl (",
        )
        .unwrap_err();
        assert!(err.contains("source 'okta'"), "{err}");
        assert!(err.contains("imported parser okta_identity"), "{err}");
    }
}
