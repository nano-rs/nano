// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3662: rows refused at lean admission, per source lane.
//!
//! **Where a lean refusal is recorded.** Every refusal ingest[T] makes is a
//! `reject` entry in the tenant's part log ([`Rejection`], one per source
//! object): the durable record that data was consumed without contributing.
//! A window in which every row is refused writes no part at all, so the
//! signed count rollup (a part partial) can never carry it; the log can.
//!
//! **Format.** [`Rejection`] is strict (`deny_unknown_fields`, a closed
//! `reason` set) and every reader of the log parses it, so a new field would
//! wedge every older reader. The per-source breakdown therefore rides in the
//! existing bounded `detail` text, as a fixed, value-free prefix:
//!
//! ```text
//! nano_refusals=v1 azure_monitor:100:ocsf_constraint_failed@device,syslog:2:time_invalid@time; <the old detail>
//! ```
//!
//! one `slug:rows:reason[@ocsf_attribute_path]` token per source lane (the
//! counter slug, [`crate::ingest_source_counters`]), largest first, at most
//! [`MAX_TAG_BYTES`]; rows of lanes that do not fit are one `*:rows` token
//! (counted on the `default` source). Every token is checked against a
//! fixed alphabet on both sides, so no row value can ride in it. The owner
//! writes the prefix only with `NANO_LAKE_REFUSAL_SOURCE_COUNTS` on; older
//! readers see a longer detail and nothing else.
//!
//! **Reading.** query[T] folds the `reject` entries it applies (and, once
//! asked, the older ones of the retained window) into a
//! [`RefusalWindow`] of 5-minute buckets keyed by the entry's append time
//! (the refusal time: a refused row may have no usable event time). An
//! untagged rejection (an older owner, or the flag off) still counts, on the
//! `default` source with the cause its detail names, so any refusal is
//! visible somewhere.

use std::collections::BTreeMap;

use serde::Serialize;

use super::part_log::Rejection;
use crate::ingest_source_counters::{RefusedSources, DEFAULT_SOURCE};

/// The detail prefix of a tagged rejection (format version 1).
pub const DETAIL_TAG: &str = "nano_refusals=v1";
/// Upper bound of the tag (the detail is cut at 480 characters; the tag
/// comes first so the cut only ever shortens the human-readable rest).
pub const MAX_TAG_BYTES: usize = 320;
/// The rollup bucket (`ROLLUP_BUCKET_SECS` on the reader side).
pub const BUCKET_MS: i64 = 300_000;
/// Distinct (bucket, source) cells a window keeps; past it new sources of a
/// bucket fold into `default` (never dropped).
pub const MAX_CELLS: usize = 50_000;
/// Reason of rows a tagged entry does not explain.
pub const UNATTRIBUTED_REASON: &str = "unattributed";
/// The env flag that turns the owner's tag on (default off).
pub const WRITE_ENV: &str = "NANO_LAKE_REFUSAL_SOURCE_COUNTS";

/// `NANO_LAKE_REFUSAL_SOURCE_COUNTS` parsed: `1`, `true` or `on`.
pub fn write_enabled_from_env(value: Option<&str>) -> bool {
    matches!(value.map(|v| v.trim().to_ascii_lowercase()).as_deref(), Some("1" | "true" | "on"))
}

/// Rows of one source lane refused in one rejection, value-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceTally {
    pub source_slug: String,
    pub rows: u64,
    /// Stable reason code (`ocsf_constraint_failed`, `time_invalid`, ...).
    pub reason: String,
    /// The OCSF attribute path the reason concerns (`device`).
    pub field: Option<String>,
}

fn is_slug(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 100
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

fn is_reason(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

fn is_field(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'[' | b']'))
}

/// One tally per source lane, largest first (then by slug). Keys that share
/// a slug (other protocol, credential or bundle) fold together; the sample
/// is the largest key's first refusal. Anything outside the alphabet is
/// replaced, never passed through.
pub fn tallies(sources: &RefusedSources) -> Vec<SourceTally> {
    let mut by_slug: BTreeMap<String, (SourceTally, u64)> = BTreeMap::new();
    for (key, source) in sources.iter() {
        let slug = if is_slug(&key.source_slug) { key.source_slug.clone() } else { DEFAULT_SOURCE.to_string() };
        let reason = if is_reason(&source.first.reason) { source.first.reason.clone() } else { "unclassified".to_string() };
        let field = source.first.field.clone().filter(|f| is_field(f));
        let entry = by_slug.entry(slug.clone()).or_insert_with(|| {
            (SourceTally { source_slug: slug, rows: 0, reason: reason.clone(), field: field.clone() }, 0)
        });
        entry.0.rows += source.rows;
        if source.rows > entry.1 {
            entry.1 = source.rows;
            entry.0.reason = reason;
            entry.0.field = field;
        }
    }
    let mut out = by_slug.into_values().map(|(tally, _)| tally).filter(|t| t.rows > 0).collect::<Vec<_>>();
    out.sort_by(|a, b| b.rows.cmp(&a.rows).then_with(|| a.source_slug.cmp(&b.source_slug)));
    out
}

fn token(tally: &SourceTally) -> String {
    match &tally.field {
        Some(field) => format!("{}:{}:{}@{field}", tally.source_slug, tally.rows, tally.reason),
        None => format!("{}:{}:{}", tally.source_slug, tally.rows, tally.reason),
    }
}

/// The tag for `tallies` (already in [`tallies`] order), within
/// [`MAX_TAG_BYTES`]; `None` when nothing was refused.
pub fn encode(tallies: &[SourceTally]) -> Option<String> {
    // Room kept for the overflow token (`,*:` + 20 digits).
    const OVERFLOW_ROOM: usize = 24;
    let mut tag = String::from(DETAIL_TAG);
    let mut overflow = 0_u64;
    let mut any = false;
    for tally in tallies.iter().filter(|t| t.rows > 0) {
        let token = token(tally);
        if tag.len() + 1 + token.len() + OVERFLOW_ROOM > MAX_TAG_BYTES {
            overflow += tally.rows;
            continue;
        }
        tag.push(if any { ',' } else { ' ' });
        tag.push_str(&token);
        any = true;
    }
    if overflow > 0 {
        tag.push(if any { ',' } else { ' ' });
        tag.push_str(&format!("*:{overflow}"));
        any = true;
    }
    any.then_some(tag)
}

/// `detail` with the tag of `tallies` in front (unchanged when empty).
pub fn tag_detail(tallies: &[SourceTally], detail: &str) -> String {
    match encode(tallies) {
        Some(tag) => format!("{tag}; {detail}"),
        None => detail.to_string(),
    }
}

/// The tallies of a tagged detail; `None` when `detail` carries no
/// well-formed tag (an older owner, the flag off, or anything malformed).
pub fn parse(detail: &str) -> Option<Vec<SourceTally>> {
    let rest = detail.strip_prefix(DETAIL_TAG)?.strip_prefix(' ')?;
    let tag = rest.split_once(';').map_or(rest, |(tag, _)| tag);
    let mut out = Vec::new();
    for token in tag.split(',') {
        let (slug, rest) = token.split_once(':')?;
        if slug == "*" {
            let rows = rest.parse::<u64>().ok()?;
            out.push(SourceTally {
                source_slug: DEFAULT_SOURCE.to_string(),
                rows,
                reason: UNATTRIBUTED_REASON.to_string(),
                field: None,
            });
            continue;
        }
        let (rows, cause) = rest.split_once(':')?;
        let rows = rows.parse::<u64>().ok()?;
        let (reason, field) = match cause.split_once('@') {
            Some((reason, field)) => (reason, Some(field)),
            None => (cause, None),
        };
        if !is_slug(slug) || !is_reason(reason) || field.is_some_and(|f| !is_field(f)) {
            return None;
        }
        out.push(SourceTally {
            source_slug: slug.to_string(),
            rows,
            reason: reason.to_string(),
            field: field.map(str::to_string),
        });
    }
    (!out.is_empty()).then_some(out)
}

/// `name=value` of a value-free `RowRefusal` rendering in an untagged
/// detail (`first_row_reason=time_invalid first_row_field=time`).
fn detail_value<'a>(detail: &'a str, name: &str) -> Option<&'a str> {
    let at = detail.find(name)?;
    let value = &detail[at + name.len()..];
    let end = value.find(|c: char| c.is_whitespace() || c == ';' || c == ',').unwrap_or(value.len());
    Some(&value[..end])
}

/// The per-source tallies of one logged rejection. A tagged one yields its
/// tokens, plus any rows the tag does not explain on `default`. An untagged
/// one counts all its rows on `default`, with the first-row cause its
/// detail names (or the coarse reason).
pub fn attribute(rejection: &Rejection) -> Vec<SourceTally> {
    let mut out = parse(&rejection.detail).unwrap_or_default();
    let tagged: u64 = out.iter().map(|t| t.rows).sum();
    let rest = rejection.rows_rejected.saturating_sub(tagged);
    if rest > 0 {
        let (reason, field) = if out.is_empty() {
            let reason = detail_value(&rejection.detail, "first_row_reason=").filter(|r| is_reason(r));
            let field = detail_value(&rejection.detail, "first_row_field=").filter(|f| is_field(f));
            (reason.unwrap_or(&rejection.reason).to_string(), reason.and(field).map(str::to_string))
        } else {
            (UNATTRIBUTED_REASON.to_string(), None)
        };
        out.push(SourceTally { source_slug: DEFAULT_SOURCE.to_string(), rows: rest, reason, field });
    }
    out.retain(|t| t.rows > 0);
    out
}

/// One (bucket, source) cell of the window.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Cell {
    rows: u64,
    reason: String,
    field: Option<String>,
    last_at_ms: i64,
}

/// One row of a refusal read (`POST /v1/ingest/refusals`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefusalRow {
    pub bucket_start_ms: i64,
    pub source: String,
    pub rows: u64,
    /// The newest refusal of the cell: reason code and OCSF attribute path.
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub last_at_ms: i64,
}

/// Refused rows per 5-minute bucket (by refusal time) and source lane,
/// bounded to the last `retain_ms` before the newest refusal seen.
#[derive(Debug, Clone)]
pub struct RefusalWindow {
    cells: BTreeMap<(i64, String), Cell>,
    retain_ms: i64,
    newest_ms: i64,
    /// Refusals are complete from this time on (`None`: not known yet, the
    /// older log is still unread).
    complete_since_ms: Option<i64>,
}

impl RefusalWindow {
    pub fn new(retain_ms: i64) -> Self {
        Self { cells: BTreeMap::new(), retain_ms, newest_ms: i64::MIN, complete_since_ms: None }
    }

    /// Fold the rejections of one `reject` entry appended at `at_ms`.
    pub fn record(&mut self, at_ms: i64, rejections: &[Rejection]) {
        if at_ms < self.newest_ms.saturating_sub(self.retain_ms) {
            return;
        }
        let bucket = at_ms.div_euclid(BUCKET_MS) * BUCKET_MS;
        for tally in rejections.iter().flat_map(attribute) {
            let mut key = (bucket, tally.source_slug);
            if !self.cells.contains_key(&key) && self.cells.len() >= MAX_CELLS {
                key.1 = DEFAULT_SOURCE.to_string();
            }
            let cell = self.cells.entry(key).or_insert_with(|| Cell {
                rows: 0,
                reason: tally.reason.clone(),
                field: tally.field.clone(),
                last_at_ms: at_ms,
            });
            cell.rows = cell.rows.saturating_add(tally.rows);
            // The newest refusal is the sample (backfill folds older ones later).
            if at_ms >= cell.last_at_ms {
                cell.last_at_ms = at_ms;
                cell.reason = tally.reason;
                cell.field = tally.field;
            }
        }
        if at_ms > self.newest_ms {
            self.newest_ms = at_ms;
            let floor = at_ms.saturating_sub(self.retain_ms).div_euclid(BUCKET_MS) * BUCKET_MS;
            self.cells.retain(|(bucket, _), _| *bucket >= floor);
        }
    }

    /// Every refusal from `at_ms` on is in the window.
    pub fn mark_complete_since(&mut self, at_ms: i64) {
        self.complete_since_ms = Some(at_ms);
    }

    pub fn complete_since_ms(&self) -> Option<i64> {
        self.complete_since_ms
    }

    /// Rows with `start_ms <= bucket_start < end_ms`, by bucket then source.
    pub fn rows(&self, start_ms: i64, end_ms: i64) -> Vec<RefusalRow> {
        self.cells
            .range((start_ms, String::new())..)
            .take_while(|((bucket, _), _)| *bucket < end_ms)
            .map(|((bucket, source), cell)| RefusalRow {
                bucket_start_ms: *bucket,
                source: source.clone(),
                rows: cell.rows,
                reason: cell.reason.clone(),
                field: cell.field.clone(),
                last_at_ms: cell.last_at_ms,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::RowRefusal;
    use crate::ingest_source_counters::SourceKey;
    use crate::parts::part_log::SourceRef;
    use serde_json::json;

    fn key(slug: &str) -> SourceKey {
        SourceKey::of(&json!({"metadata": {"log_source": slug, "ingress_transport": "hec"}}))
    }

    fn rejection(rows: u64, detail: &str) -> Rejection {
        Rejection {
            source: SourceRef { key: "bronze/a.parquet".into(), version: "1".into(), sha256: "a".repeat(64) },
            scope: "object".into(),
            rows_rejected: rows,
            reason: "admission_invalid".into(),
            detail: detail.into(),
        }
    }

    /// The tenant-b case: 100 Entra SignInLogs rows whose `device` names
    /// no identifier, refused by the strict OCSF constraint.
    fn sign_in_logs(rows: u64) -> RefusedSources {
        let mut sources = RefusedSources::default();
        let device = RowRefusal::new("ocsf_constraint_failed", Some("device"));
        for _ in 0..rows {
            sources.note(key("azure_monitor"), &device, None);
        }
        sources
    }

    #[test]
    fn the_sign_in_logs_refusal_round_trips_value_free() {
        let tallies = tallies(&sign_in_logs(100));
        assert_eq!(tallies, vec![SourceTally {
            source_slug: "azure_monitor".into(),
            rows: 100,
            reason: "ocsf_constraint_failed".into(),
            field: Some("device".into()),
        }]);
        let detail = tag_detail(&tallies, "bronze admission produced no canonical events; first_row_reason=ocsf_constraint_failed first_row_field=device");
        assert!(detail.starts_with("nano_refusals=v1 azure_monitor:100:ocsf_constraint_failed@device; bronze admission"), "{detail}");
        assert_eq!(parse(&detail).unwrap(), tallies);
        assert_eq!(attribute(&rejection(100, &detail)), tallies);
    }

    #[test]
    fn tallies_fold_keys_of_one_slug_and_sort_largest_first() {
        let mut sources = sign_in_logs(3);
        let time = RowRefusal::new("time_invalid", Some("time"));
        sources.note(SourceKey::of(&json!({"metadata": {"log_source": "azure_monitor", "ingress_transport": "otlp"}})), &time, None);
        for _ in 0..5 {
            sources.note(key("syslog"), &time, None);
        }
        let tallies = tallies(&sources);
        let summary = tallies.iter().map(|t| (t.source_slug.as_str(), t.rows, t.reason.as_str())).collect::<Vec<_>>();
        assert_eq!(summary, vec![("syslog", 5, "time_invalid"), ("azure_monitor", 4, "ocsf_constraint_failed")]);
    }

    #[test]
    fn a_long_tag_stays_bounded_and_counts_every_row() {
        let mut sources = RefusedSources::default();
        let refusal = RowRefusal::new("ocsf_attribute_required_missing", Some("metadata.product.vendor_name"));
        for lane in 0..40 {
            for _ in 0..=lane {
                sources.note(key(&format!("lane_{lane:02}_with_a_long_name")), &refusal, None);
            }
        }
        let tallies = tallies(&sources);
        let tag = encode(&tallies).unwrap();
        assert!(tag.len() <= MAX_TAG_BYTES, "{}", tag.len());
        let parsed = parse(&tag).unwrap();
        assert_eq!(parsed.iter().map(|t| t.rows).sum::<u64>(), (1..=40).sum::<u64>());
        assert_eq!(parsed.first().unwrap().source_slug, "lane_39_with_a_long_name");
        let overflow = parsed.last().unwrap();
        assert_eq!((overflow.source_slug.as_str(), overflow.reason.as_str()), ("default", UNATTRIBUTED_REASON));
    }

    #[test]
    fn malformed_tags_are_not_trusted() {
        for detail in [
            "nano_refusals=v1",
            "nano_refusals=v1 ",
            "nano_refusals=v1 Azure:1:x",
            "nano_refusals=v1 azure:one:x",
            "nano_refusals=v1 azure:1:bad reason",
            "nano_refusals=v1 azure:1:x@user=alice@example.com",
            "nano_refusals=v2 azure:1:x",
            "first_row_reason=x",
        ] {
            assert_eq!(parse(detail), None, "{detail}");
        }
    }

    /// Old format (an older owner, or the flag off): every row still counts,
    /// on `default`, with the first-row cause the detail already names.
    #[test]
    fn untagged_rejections_count_on_the_default_source() {
        let old = rejection(7, "7 rows refused; first_row_reason=ocsf_constraint_failed first_row_field=device");
        assert_eq!(attribute(&old), vec![SourceTally {
            source_slug: "default".into(),
            rows: 7,
            reason: "ocsf_constraint_failed".into(),
            field: Some("device".into()),
        }]);
        let coarse = rejection(3, "rows do not decode into the tenant schema");
        assert_eq!(attribute(&coarse)[0].reason, "admission_invalid");
        assert!(attribute(&rejection(0, "notified object not found")).is_empty());
        // A tag that explains fewer rows than were refused: the rest is unattributed.
        let short = rejection(5, "nano_refusals=v1 azure_monitor:3:time_invalid@time; 5 rows refused");
        let summary = attribute(&short).iter().map(|t| (t.source_slug.clone(), t.rows, t.reason.clone())).collect::<Vec<_>>();
        assert_eq!(summary, vec![("azure_monitor".into(), 3, "time_invalid".into()), ("default".into(), 2, UNATTRIBUTED_REASON.into())]);
    }

    #[test]
    fn the_window_buckets_by_refusal_time_keeps_the_newest_sample_and_prunes() {
        let hour = 3_600_000;
        let mut window = RefusalWindow::new(48 * hour);
        let t0 = 1_791_790_000_000 - 1_791_790_000_000 % BUCKET_MS;
        let tagged = tag_detail(&tallies(&sign_in_logs(100)), "x");
        window.record(t0 + 1_000, &[rejection(100, &tagged)]);
        window.record(t0 + 2_000, &[rejection(4, "nano_refusals=v1 azure_monitor:4:time_invalid@time; x")]);
        // Backfilled older entry: counted, but not the sample.
        window.record(t0 + 500, &[rejection(1, "nano_refusals=v1 azure_monitor:1:schema_decode; x")]);
        let rows = window.rows(t0, t0 + BUCKET_MS);
        assert_eq!(rows, vec![RefusalRow {
            bucket_start_ms: t0,
            source: "azure_monitor".into(),
            rows: 105,
            reason: "time_invalid".into(),
            field: Some("time".into()),
            last_at_ms: t0 + 2_000,
        }]);
        assert!(window.rows(t0 + BUCKET_MS, t0 + 2 * BUCKET_MS).is_empty());
        // 49 h later the first bucket falls out; older appends are ignored.
        window.record(t0 + 49 * hour, &[rejection(1, "x")]);
        assert!(window.rows(t0, t0 + BUCKET_MS).is_empty());
        window.record(t0, &[rejection(1, "x")]);
        assert!(window.rows(t0, t0 + BUCKET_MS).is_empty());
        let payload = serde_json::to_value(window.rows(0, i64::MAX)).unwrap();
        assert_eq!(payload[0]["source"], "default");
        assert!(payload[0].get("field").is_none());
    }

    #[test]
    fn the_write_flag_is_default_off() {
        assert!(!write_enabled_from_env(None));
        assert!(!write_enabled_from_env(Some("0")));
        assert!(!write_enabled_from_env(Some("")));
        assert!(write_enabled_from_env(Some("1")));
        assert!(write_enabled_from_env(Some(" ON ")));
    }
}
