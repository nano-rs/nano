// SPDX-License-Identifier: AGPL-3.0-or-later

//! Entity baselining primitives (NAN-1864) — what is NORMAL for a user / host / ip.
//!
//! These are the pure computation primitives, lifted into `nanosiem-core`
//! (NAN-1868) so BOTH the enterprise shadow investigator and the core `| baseline`
//! search command can use them without either reimplementing the anti-join or the
//! gating. They pair with the entity-keyed `SearchService` methods
//! (`entity_dimension_firsts` / `entity_activity_buckets` /
//! `entity_hourly_activity_scoped`) in `search::service::asset`.
//!
//! # The two traps this module exists to avoid
//!
//! 1. **The baseline window EXCLUDES the current/incident window.** [`BaselineSpans`]
//!    ends the history at the incident window's start. Include it and a noisy
//!    alert (10k failed logins) becomes its own baseline and normalises itself.
//!
//! 2. **An empty baseline is not an anomalous baseline.** A brand-new user or a
//!    freshly-imaged host has no history, so EVERY value it touches is trivially
//!    "never seen before". [`BaselineCoverage`] gates this: with no history the
//!    new-to-entity list is suppressed; on thin history it is shown but flagged.
//!    Absence of evidence is reported as absence of evidence — never as evidence.

use chrono::{DateTime, Duration, Timelike, Utc};
use std::collections::HashMap;

/// Days of ACTIVITY history to profile an entity's rhythm/volume against
/// (agg-served, cheap). Override with `NANOSIEM_SHADOW_BASELINE_ACTIVITY_DAYS`.
pub const DEFAULT_ACTIVITY_DAYS: i64 = 30;

/// Days the NEW-TO-ENTITY check looks back. Deliberately SHORT and separate from
/// the activity window — it scans raw `logs` (no cheap path), ~110 MiB/day per
/// dimension on a 2B-row tenant. 7 days catches the common attack tempo (LOLBin /
/// lateral movement land within days). Override with
/// `NANOSIEM_SHADOW_BASELINE_NEW_WINDOW_DAYS`.
pub const DEFAULT_NEW_WINDOW_DAYS: i64 = 7;

/// Minimum distinct ACTIVE days within the new-to-entity window before "never
/// seen before" is a claim we are willing to make.
pub const MIN_BASELINE_DAYS: u64 = 3;

/// Minimum events within the new-to-entity window before "never seen before" is a
/// claim we are willing to make.
pub const MIN_BASELINE_EVENTS: u64 = 50;

/// Row cap the consolidated arrayJoin scan applies per dimension (`LIMIT n BY dim`).
pub const NEW_TO_ENTITY_ROW_CAP: usize = 100;

/// Known peers kept per dimension. A LOWER BOUND once the row cap bites (the query
/// sorts first_seen DESC, so the OLDEST — most characteristic — values drop first).
pub const MAX_PEERS_SHOWN: usize = 12;

/// New-to-entity values kept per dimension.
const MAX_NEW_SHOWN: usize = 15;

/// Env-configurable positive day count within `[1, 365]`, or the default.
fn env_days(var: &str, default: i64) -> i64 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|d| (1..=365).contains(d))
        .unwrap_or(default)
}

/// Days of activity history for rhythm/volume (agg-served, cheap).
pub fn activity_days() -> i64 {
    env_days("NANOSIEM_SHADOW_BASELINE_ACTIVITY_DAYS", DEFAULT_ACTIVITY_DAYS)
}

/// Days the new-to-entity check looks back (raw-log scan, deliberately short).
pub fn new_window_days() -> i64 {
    env_days(
        "NANOSIEM_SHADOW_BASELINE_NEW_WINDOW_DAYS",
        DEFAULT_NEW_WINDOW_DAYS,
    )
}

/// The time spans baselining reasons over. Two histories, deliberately distinct,
/// because they answer different questions at very different costs:
///
/// - `[activity_start, incident_start)` — the ACTIVITY window (default 30d).
///   Rhythm/volume come from `entity_time_range_agg` over this span (keyed lookup).
/// - `[new_start, incident_start)` — the NEW-TO-ENTITY history (default 7d).
///   `[new_start, incident_end]` is scanned in one grouped query and split on
///   `incident_start`: a value first-seen at/after the incident was absent from
///   the 7d history and is "new". This scans raw `logs`, so it is kept short.
///
/// Both histories END at `incident_start` — the current window itself is excluded,
/// so a noisy window can never normalise itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineSpans {
    pub activity_start: DateTime<Utc>,
    pub new_start: DateTime<Utc>,
    /// Exclusive end of both histories == start of the current/incident window.
    pub incident_start: DateTime<Utc>,
    pub incident_end: DateTime<Utc>,
    pub activity_days: i64,
    pub new_window_days: i64,
}

impl BaselineSpans {
    /// Build the spans for a current window `[incident_start, incident_end]`.
    pub fn new(
        incident_start: DateTime<Utc>,
        incident_end: DateTime<Utc>,
        activity_days: i64,
        new_window_days: i64,
    ) -> Self {
        Self {
            activity_start: incident_start - Duration::days(activity_days),
            new_start: incident_start - Duration::days(new_window_days),
            incident_start,
            incident_end,
            activity_days,
            new_window_days,
        }
    }

    /// Length of the current window in minutes — used to normalise its event count
    /// to a per-hour rate for the volume comparison.
    pub fn incident_minutes(&self) -> i64 {
        (self.incident_end - self.incident_start).num_minutes().max(1)
    }

    /// Exclusive upper bound for agg buckets — the start of the incident's clock
    /// hour, NOT `incident_start` itself.
    ///
    /// Agg buckets are hour-aligned (`toStartOfHour`), but `incident_start` is
    /// sub-hour. The bucket whose hour CONTAINS `incident_start` has
    /// `time_bucket < incident_start`, so a naive `< incident_start` filter lets it
    /// through — yet its `event_count` includes the incident's own events. For a
    /// fresh entity that flips `NoHistory → Thin` off the alert's own events.
    /// Truncating to the hour drops the straddling bucket.
    pub fn coverage_end(&self) -> DateTime<Utc> {
        self.incident_start
            .with_minute(0)
            .and_then(|t| t.with_second(0))
            .and_then(|t| t.with_nanosecond(0))
            .unwrap_or(self.incident_start)
    }

    /// The hour the current window is centred on, for the rhythm comparison — the
    /// window midpoint, NOT `incident_start.hour()` (the window starts before the
    /// event, so the start hour can be an hour early).
    pub fn event_hour(&self) -> u32 {
        let mid = self.incident_start + (self.incident_end - self.incident_start) / 2;
        mid.hour()
    }
}

/// How much history an entity has, and therefore how much weight its baseline can
/// carry. The guard against "empty baseline reads as anomaly".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineCoverage {
    /// Enough history to call something abnormal.
    Sufficient { active_days: u64, total_events: u64 },
    /// Some history, but not enough for "never seen before" to mean anything.
    Thin { active_days: u64, total_events: u64 },
    /// No history at all — the new-to-entity list is suppressed.
    NoHistory,
}

impl BaselineCoverage {
    pub fn classify(active_days: u64, total_events: u64) -> Self {
        if total_events == 0 || active_days == 0 {
            Self::NoHistory
        } else if active_days < MIN_BASELINE_DAYS || total_events < MIN_BASELINE_EVENTS {
            Self::Thin {
                active_days,
                total_events,
            }
        } else {
            Self::Sufficient {
                active_days,
                total_events,
            }
        }
    }

    /// True only when a "never seen before" claim is worth making unqualified.
    pub fn is_trustworthy(&self) -> bool {
        matches!(self, Self::Sufficient { .. })
    }

    /// True when the entity has NO history and new-to-entity must be suppressed.
    pub fn is_blind(&self) -> bool {
        matches!(self, Self::NoHistory)
    }

    /// A short stable label for result rows / JSON: `sufficient` | `thin` | `no_history`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Sufficient { .. } => "sufficient",
            Self::Thin { .. } => "thin",
            Self::NoHistory => "no_history",
        }
    }
}

/// Which side of an event the entity has to be on for a dimension to be ABOUT that
/// entity. Load-bearing: bi-directional matching for "what did X *do*" credits
/// another machine's actions to X (a remote host RDP'ing IN would otherwise land
/// in X's process baseline). See NAN-1864.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DimScope {
    /// The entity DID this — pin to the actor (source) side.
    Actor,
    /// The entity was merely INVOLVED — bi-directional is correct.
    Association,
}

/// One dimension of an entity's behaviour (hosts a user logs into, processes a
/// host runs, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dimension {
    /// UDM field name; resolved per-profile by the search layer.
    pub field: &'static str,
    /// Human label for output rows / the prompt.
    pub label: &'static str,
    pub scope: DimScope,
}

/// Dimensions worth profiling for an entity type, gated on which data classes
/// exist so we never group by a column nothing populates.
pub fn dimensions_for(
    entity_type: &str,
    has_process: bool,
    has_network: bool,
    has_auth: bool,
) -> Vec<Dimension> {
    let mut dims: Vec<Dimension> = Vec::new();
    match entity_type {
        // `user`/`src_user` is a field-name difference, not a direction of travel —
        // no "destination user" to misattribute — so every user dimension is Actor.
        "user" => {
            dims.push(Dimension {
                field: "src_host",
                label: "hosts",
                scope: DimScope::Actor,
            });
            if has_auth || has_network {
                dims.push(Dimension {
                    field: "src_ip",
                    label: "source IPs",
                    scope: DimScope::Actor,
                });
            }
            if has_process {
                dims.push(Dimension {
                    field: "process_name",
                    label: "processes",
                    scope: DimScope::Actor,
                });
            }
        }
        "host" => {
            // "A new user appeared on this host" is true whichever side the host is on.
            dims.push(Dimension {
                field: "user",
                label: "users",
                scope: DimScope::Association,
            });
            // These MUST be actor-anchored — see [`DimScope`].
            if has_process {
                dims.push(Dimension {
                    field: "process_name",
                    label: "processes",
                    scope: DimScope::Actor,
                });
            }
            if has_network {
                dims.push(Dimension {
                    field: "dest_ip",
                    label: "destination IPs",
                    scope: DimScope::Actor,
                });
            }
        }
        // An IP's role is genuinely unknown up front — Association is honest.
        "ip" => {
            dims.push(Dimension {
                field: "src_host",
                label: "hosts",
                scope: DimScope::Association,
            });
            if has_network {
                dims.push(Dimension {
                    field: "dest_port",
                    label: "ports",
                    scope: DimScope::Association,
                });
            }
            if has_auth {
                dims.push(Dimension {
                    field: "user",
                    label: "users",
                    scope: DimScope::Association,
                });
            }
        }
        _ => {}
    }
    dims
}

/// Group an entity's dimensions by the entity FILTER they need, so each group is
/// one consolidated `entity_dimension_firsts` scan. Actor dims share the
/// source-side filter; Association dims share the bi-directional one. Most entities
/// collapse to 1-2 groups.
pub fn dimension_scope_groups(
    entity_type: &str,
    has_process: bool,
    has_network: bool,
    has_auth: bool,
) -> Vec<(bool, Vec<Dimension>)> {
    let (actor, assoc): (Vec<Dimension>, Vec<Dimension>) =
        dimensions_for(entity_type, has_process, has_network, has_auth)
            .into_iter()
            .partition(|d| d.scope == DimScope::Actor);
    let mut groups = Vec::new();
    if !actor.is_empty() {
        groups.push((true, actor));
    }
    if !assoc.is_empty() {
        groups.push((false, assoc));
    }
    groups
}

/// Entity types with a meaningful behavioural baseline. Artifacts (hash/domain/
/// file) are covered by the ARTIFACT-keyed prevalence stack instead.
pub fn is_baselineable(entity_type: &str) -> bool {
    matches!(entity_type, "user" | "host" | "ip")
}

/// Coverage + rhythm + volume distribution for an entity, computed from its hourly
/// activity buckets.
#[derive(Debug, Clone, PartialEq)]
pub struct ActivitySummary {
    pub coverage: BaselineCoverage,
    pub mean_per_day: f64,
    /// hour-of-day (0..23) → summed events over the activity window.
    pub active_hours: Vec<(u32, u64)>,
    hourly_counts: Vec<u64>,
}

impl ActivitySummary {
    /// Per-active-hour counts feeding the volume comparison. Empty ⇒ the entity
    /// had no activity at all in the window (truly blind).
    pub fn hourly_counts(&self) -> &[u64] {
        &self.hourly_counts
    }
}

/// Fold hourly activity buckets into an [`ActivitySummary`]. Rhythm/volume use ALL
/// activity-window buckets; coverage uses only the (shorter) new-window subset,
/// because coverage's job is whether "absent from the new window" is trustworthy.
/// The activity window is upper-bounded at [`BaselineSpans::coverage_end`] to drop
/// the straddling incident-hour bucket.
pub fn summarize_activity(buckets: &[(DateTime<Utc>, u64)], spans: &BaselineSpans) -> ActivitySummary {
    use std::collections::BTreeSet;

    let mut hour_hist: HashMap<u32, u64> = HashMap::new();
    let mut hourly_counts: Vec<u64> = Vec::new();
    let mut total_events: u64 = 0;
    let mut active_dates: BTreeSet<chrono::NaiveDate> = BTreeSet::new();
    let mut new_events: u64 = 0;
    let mut new_dates: BTreeSet<chrono::NaiveDate> = BTreeSet::new();

    let coverage_end = spans.coverage_end();
    for (ts, count) in buckets {
        if *count == 0 || *ts < spans.activity_start || *ts >= coverage_end {
            continue;
        }
        *hour_hist.entry(ts.hour()).or_insert(0) += *count;
        hourly_counts.push(*count);
        total_events += *count;
        active_dates.insert(ts.date_naive());

        if *ts >= spans.new_start {
            new_events += *count;
            new_dates.insert(ts.date_naive());
        }
    }

    let mut active_hours: Vec<(u32, u64)> = hour_hist.into_iter().collect();
    active_hours.sort_unstable_by_key(|(h, _)| *h);

    let coverage = BaselineCoverage::classify(new_dates.len() as u64, new_events);
    let active_days = active_dates.len().max(1) as f64;
    let mean_per_day = total_events as f64 / active_days;

    ActivitySummary {
        coverage,
        mean_per_day,
        active_hours,
        hourly_counts,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PeerValue {
    pub value: String,
    pub count: u64,
    pub first_seen: DateTime<Utc>,
}

/// One dimension's known/new split for an entity.
#[derive(Debug, Clone, PartialEq)]
pub struct DimensionBaseline {
    pub label: &'static str,
    /// Values already used BEFORE the current window, most frequent first.
    pub known: Vec<PeerValue>,
    /// Distinct known values seen — a LOWER BOUND when [`Self::truncated`].
    pub known_cardinality: usize,
    /// Values first-seen for this entity inside the current window. Always EMPTY
    /// when coverage is [`BaselineCoverage::NoHistory`] (new is vacuous).
    pub new_to_entity: Vec<PeerValue>,
    /// The row cap was hit, so `known` is partial. Never affects `new_to_entity`.
    pub truncated: bool,
    /// The row cap filled ENTIRELY with new values, so no history was visible —
    /// either never-observed OR 100+ first-sightings at once (a scan). Reported
    /// with a caveat, never as confirmed "never seen before".
    pub baseline_unknown: bool,
}

/// True for values that are not real peers — empty strings and nulls. ClickHouse
/// groups these into a bucket like any other, so drop them or every entity gets a
/// bogus `""` peer.
fn is_empty_value(v: &str) -> bool {
    v.trim().is_empty() || v == "-" || v.eq_ignore_ascii_case("null")
}

/// Split one dimension's `(value, count, first_seen)` rows (from the consolidated
/// arrayJoin scan) into known / new. `truncated` is `rows.len() >= per_dim_limit`.
pub fn parse_dimension_firsts(
    label: &'static str,
    rows: Vec<(String, u64, DateTime<Utc>)>,
    per_dim_limit: usize,
    incident_start: DateTime<Utc>,
    coverage: BaselineCoverage,
) -> DimensionBaseline {
    let truncated = rows.len() >= per_dim_limit;
    parse_dimension_core(label, rows, truncated, incident_start, coverage)
}

/// The new-to-entity split over already-extracted rows. `coverage` gates whether
/// the split is meaningful: with [`BaselineCoverage::NoHistory`] every value is
/// trivially new and `new_to_entity` is suppressed.
fn parse_dimension_core(
    label: &'static str,
    rows: Vec<(String, u64, DateTime<Utc>)>,
    truncated: bool,
    incident_start: DateTime<Utc>,
    coverage: BaselineCoverage,
) -> DimensionBaseline {
    let mut known: Vec<PeerValue> = Vec::new();
    let mut fresh: Vec<PeerValue> = Vec::new();

    for (value, count, first_seen) in rows {
        if is_empty_value(&value) {
            continue;
        }
        let peer = PeerValue {
            value,
            count,
            first_seen,
        };
        if first_seen >= incident_start {
            fresh.push(peer);
        } else {
            known.push(peer);
        }
    }

    let known_cardinality = known.len();
    known.sort_unstable_by(|a, b| b.count.cmp(&a.count));
    known.truncate(MAX_PEERS_SHOWN);
    fresh.sort_unstable_by(|a, b| b.count.cmp(&a.count));
    fresh.truncate(MAX_NEW_SHOWN);

    // Suppress "new" only when the result is COMPLETE and empty of history. If the
    // cap was hit and every row is new, the known values may just have been pushed
    // off the page (a scan) — report them but flag the baseline as unestablished.
    let complete_and_never_watched = known_cardinality == 0 && !truncated;
    let baseline_unknown = known_cardinality == 0 && truncated && !fresh.is_empty();
    let blind = coverage.is_blind() || complete_and_never_watched;

    DimensionBaseline {
        label,
        known,
        known_cardinality,
        new_to_entity: if blind { Vec::new() } else { fresh },
        truncated,
        baseline_unknown: baseline_unknown && !coverage.is_blind(),
    }
}
