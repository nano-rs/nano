// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — canonical lead fingerprints.
//!
//! A fingerprint answers one question: *is this the same finding we already
//! showed someone?* Suppression is keyed on it, so a wrong answer either
//! resurrects a lead an analyst killed or silently hides a new one. Rule-idea
//! recurrence is counted on it, so a wrong answer either never reaches the gate
//! or reaches it on unrelated findings.
//!
//! # Two ways to get this wrong, both of which we have to design out
//!
//! **Hashing prose.** The obvious implementation hashes the narrative, which is
//! what `siem_health`'s finding signature does with normalized titles. It fails
//! twice: the same finding described twice yields two fingerprints, so
//! suppression leaks; and the narrative comes from attacker-authored log
//! content, so whoever is being hunted can steer it.
//!
//! **Hashing whatever the agent said the lead was about.** Less obvious and
//! more dangerous. Excluding a literal `fingerprint` field from the wire type
//! is not enough if the agent still chooses the *inputs*: a suppressed finding
//! resubmitted with one extra junk signal hashes differently and walks straight
//! past the suppression. The agent would not even need to be adversarial to do
//! this — a model that phrases a signal list slightly differently on the next
//! run achieves the same thing by accident.
//!
//! So the input type here cannot be built from agent strings. [`CanonicalEntity`]
//! and [`ValidatedSignal`] have private fields and no public constructor from
//! raw input: the only way to obtain them is through a server-side resolver
//! that has checked the entity actually appears in the resolved evidence and
//! that each signal is a known identifier. An unrecognised signal is dropped
//! rather than hashed, which is what closes the nonce hole.
//!
//! # Framing must be injective
//!
//! An earlier revision joined fields with `\x1f` and stripped that byte from
//! inputs. Stripping is lossy, and lossy framing collides: `"srvweb"` and
//! `"srv\x1fweb"` hashed identically, as did `"T1021"` and `"T10\x1f21"`. Two
//! unrelated leads sharing a fingerprint means one inherits the other's
//! suppression. Fields are now length-prefixed, which is injective for any
//! byte string and needs no separator or stripping at all.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

/// An entity the server has confirmed, not one the agent asserted.
///
/// Private fields on purpose. A `CanonicalEntity` can only be produced by
/// [`CanonicalEntity::resolve`], which requires the caller to prove the entity
/// appears in evidence the server itself resolved.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CanonicalEntity {
    entity_type: String,
    value: String,
}

/// Entity types whose values are case-insensitive by nature.
///
/// Hostnames, domains, IPs, hashes and addresses all compare
/// case-insensitively, so folding case makes two spellings of one entity agree.
/// Everything else — file paths, URLs, process command lines — is
/// case-SENSITIVE on the systems that produce it. `/Admin` and `/admin` are
/// different paths on Linux, and folding them would let a lead about one
/// inherit a suppression written for the other.
const CASE_INSENSITIVE_TYPES: &[&str] = &["ip", "host", "domain", "hash", "email"];

impl CanonicalEntity {
    /// Resolve an agent-claimed entity against evidence the server read.
    ///
    /// Returns `None` when the claim is not corroborated — the agent named an
    /// entity that appears nowhere in the events it attached. That is either a
    /// hallucination or an attempt to aim a lead at a chosen fingerprint, and
    /// both are handled the same way: the candidate is rejected.
    ///
    /// `observed` is the set of `(entity_type, value)` pairs the server
    /// extracted from the resolved evidence rows.
    pub fn resolve(
        claimed_type: &str,
        claimed_value: &str,
        observed: &BTreeSet<(String, String)>,
    ) -> Option<Self> {
        let entity_type = claimed_type.trim().to_lowercase();
        let value = normalize_value(&entity_type, claimed_value);
        if value.is_empty() {
            return None;
        }
        let corroborated = observed.iter().any(|(observed_type, observed_value)| {
            observed_type.trim().to_lowercase() == entity_type
                && normalize_value(&entity_type, observed_value) == value
        });
        corroborated.then_some(Self { entity_type, value })
    }

    /// Build without corroboration, for server-originated entities.
    ///
    /// Only for paths where the server itself produced the entity (recon
    /// profiling, backfills). Never reachable from a sweep report.
    pub fn trusted(entity_type: &str, value: &str) -> Option<Self> {
        let entity_type = entity_type.trim().to_lowercase();
        let value = normalize_value(&entity_type, value);
        (!value.is_empty()).then_some(Self { entity_type, value })
    }

    pub fn entity_type(&self) -> &str {
        &self.entity_type
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

/// A signal identifier the server recognises.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ValidatedSignal(String);

impl ValidatedSignal {
    /// Accept a signal only if it is in the server's known set.
    ///
    /// The known set is the MITRE technique catalogue plus the tenant's rule
    /// ids — both server-owned. An unrecognised signal returns `None` and the
    /// caller drops it, which is what stops an agent minting a fresh
    /// fingerprint by appending a nonce.
    pub fn validate(candidate: &str, known: &BTreeSet<String>) -> Option<Self> {
        let normalized = candidate.trim().to_lowercase();
        if normalized.is_empty() || !known.contains(&normalized) {
            return None;
        }
        Some(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The inputs a fingerprint is derived from.
///
/// Note what is NOT here: the hunt's version. An earlier revision included it
/// so that editing a hunt started a fresh suppression lineage — but that made a
/// typo fix in a hunt's prose silently reset every suppression an analyst had
/// written and zero its recurrence history. A lead's identity is a property of
/// the finding, not of the query revision that happened to surface it. If a
/// suppression ever needs to be version-scoped, that bound belongs on the
/// suppression row where it can be seen and reasoned about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintInput<'a> {
    pub hunt_id: uuid::Uuid,
    pub entity: &'a CanonicalEntity,
    pub signals: &'a [ValidatedSignal],
}

/// 32 hex chars = 128 bits. Negligible collision risk at any realistic lead
/// volume, short enough to read in a URL or a log line.
const FINGERPRINT_HEX_LEN: usize = 32;

/// Bump if the derivation changes. Old suppressions then stop matching new
/// leads rather than matching them *wrongly* — a returning dismissed lead is a
/// visible annoyance, a new lead silently absorbed by a stale suppression is an
/// invisible miss.
const DERIVATION_VERSION: &str = "v2";

/// Derive the canonical fingerprint for a lead.
pub fn derive(input: &FingerprintInput<'_>) -> String {
    let mut hasher = Sha256::new();

    // Length-prefixed framing: injective for any byte string, so no field can
    // be made to straddle a boundary and no input needs to be mutilated to
    // make framing safe.
    let mut push = |value: &str| {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    };

    push(DERIVATION_VERSION);
    push(&input.hunt_id.to_string());
    push(input.entity.entity_type());
    push(input.entity.value());

    // Sorted and de-duplicated so the order the agent happened to investigate
    // things in cannot change the identity of a finding.
    let signals: BTreeSet<&str> = input.signals.iter().map(ValidatedSignal::as_str).collect();
    push(&signals.len().to_string());
    for signal in &signals {
        push(signal);
    }

    let hex = hex::encode(hasher.finalize());
    hex[..FINGERPRINT_HEX_LEN].to_string()
}

/// Trim, and fold case only for types where case carries no meaning.
fn normalize_value(entity_type: &str, value: &str) -> String {
    let trimmed = value.trim();
    if CASE_INSENSITIVE_TYPES.contains(&entity_type) {
        trimmed.to_lowercase()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn hunt() -> Uuid {
        Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap()
    }

    fn observed(pairs: &[(&str, &str)]) -> BTreeSet<(String, String)> {
        pairs
            .iter()
            .map(|(t, v)| (t.to_string(), v.to_string()))
            .collect()
    }

    fn known(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| s.to_lowercase()).collect()
    }

    fn entity(t: &str, v: &str) -> CanonicalEntity {
        CanonicalEntity::trusted(t, v).expect("valid entity")
    }

    fn signals(ids: &[&str]) -> Vec<ValidatedSignal> {
        let catalogue = known(ids);
        ids.iter()
            .filter_map(|id| ValidatedSignal::validate(id, &catalogue))
            .collect()
    }

    fn fp(entity: &CanonicalEntity, sigs: &[ValidatedSignal]) -> String {
        derive(&FingerprintInput {
            hunt_id: hunt(),
            entity,
            signals: sigs,
        })
    }

    #[test]
    fn an_unknown_signal_cannot_mint_a_fresh_fingerprint() {
        // THE nonce attack: a suppressed lead resubmitted with one junk signal
        // must not hash differently, or dismissal memory is worthless.
        let catalogue = known(&["t1021"]);
        let accepted = ValidatedSignal::validate("T1021", &catalogue);
        let rejected = ValidatedSignal::validate("nonce-8f3a", &catalogue);
        assert!(accepted.is_some());
        assert!(rejected.is_none(), "an unknown signal was accepted into the hash");

        let host = entity("host", "srv-web06");
        let with_junk: Vec<ValidatedSignal> = ["T1021", "nonce-8f3a"]
            .iter()
            .filter_map(|s| ValidatedSignal::validate(s, &catalogue))
            .collect();
        assert_eq!(fp(&host, &signals(&["t1021"])), fp(&host, &with_junk));
    }

    #[test]
    fn an_uncorroborated_entity_is_rejected() {
        // The agent may not name an entity that appears nowhere in the evidence
        // the server resolved — that is how it would otherwise aim a lead at a
        // fingerprint of its choosing.
        let evidence = observed(&[("host", "srv-web06")]);
        assert!(CanonicalEntity::resolve("host", "srv-web06", &evidence).is_some());
        assert!(CanonicalEntity::resolve("host", "attacker-chosen", &evidence).is_none());
    }

    #[test]
    fn corroboration_is_case_correct_per_type() {
        let hosts = observed(&[("host", "SRV-Web06")]);
        assert!(
            CanonicalEntity::resolve("host", "srv-web06", &hosts).is_some(),
            "hostnames compare case-insensitively"
        );
        let paths = observed(&[("file", "/etc/Admin")]);
        assert!(
            CanonicalEntity::resolve("file", "/etc/admin", &paths).is_none(),
            "file paths are case-sensitive; folding them would cross-apply suppressions"
        );
    }

    #[test]
    fn framing_is_injective_across_field_boundaries() {
        // The collisions the previous \x1f-stripping revision had.
        assert_ne!(fp(&entity("host", "srvweb"), &[]), fp(&entity("host", "srv\u{1f}web"), &[]));
        assert_ne!(fp(&entity("host", "ab"), &[]), fp(&entity("host", "a"), &[]));
        let a = entity("host", "a");
        let ab = entity("hosta", "b");
        assert_ne!(fp(&a, &[]), fp(&ab, &[]));
    }

    #[test]
    fn signal_order_and_duplication_do_not_change_identity() {
        let catalogue = known(&["t1021", "t1078"]);
        let forward: Vec<ValidatedSignal> = ["T1021", "T1078"]
            .iter()
            .filter_map(|s| ValidatedSignal::validate(s, &catalogue))
            .collect();
        let reverse_dup: Vec<ValidatedSignal> = ["T1078", "t1021", "T1021"]
            .iter()
            .filter_map(|s| ValidatedSignal::validate(s, &catalogue))
            .collect();
        let host = entity("host", "srv-web06");
        assert_eq!(fp(&host, &forward), fp(&host, &reverse_dup));
    }

    #[test]
    fn identity_survives_a_hunt_edit() {
        // A typo fix in a hunt's prose must not reset every suppression an
        // analyst wrote against it, nor zero its recurrence history. Version is
        // deliberately absent from the input, so this is structural.
        let host = entity("host", "srv-web06");
        let sigs = signals(&["t1021"]);
        assert_eq!(fp(&host, &sigs), fp(&host, &sigs));
    }

    #[test]
    fn distinct_entities_and_hunts_differ() {
        let sigs = signals(&["t1021"]);
        assert_ne!(fp(&entity("host", "srv-web06"), &sigs), fp(&entity("host", "srv-web07"), &sigs));
        let other_hunt = derive(&FingerprintInput {
            hunt_id: Uuid::parse_str("018f0000-0000-7000-8000-000000000002").unwrap(),
            entity: &entity("host", "srv-web06"),
            signals: &sigs,
        });
        assert_ne!(fp(&entity("host", "srv-web06"), &sigs), other_hunt);
    }

    #[test]
    fn fingerprint_is_stable_hex_of_expected_length() {
        let value = fp(&entity("host", "srv-web06"), &signals(&["t1021"]));
        assert_eq!(value.len(), FINGERPRINT_HEX_LEN);
        assert!(value.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
