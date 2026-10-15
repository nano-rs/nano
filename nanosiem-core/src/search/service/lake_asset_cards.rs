// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3262: the lean Asset dossier's cards as lake aggregates.
//!
//! The dossier used to wait for the shared snapshot's full event read: every
//! matching event of the window, 42 projected columns each, newest first
//! (live: 27,503 rows, `scan_ms=55441` for one host-hour), and then folded
//! those rows into seven small cards. Every early poll was empty because the
//! first (and, for an hour, only) chunk of that read had not landed.
//!
//! Now each card is a grouped `stats` the lake answers in one pass over the
//! few columns it names, and only the small group rows travel back:
//!
//! - **identity**: one group per distinct endpoint / user / product tuple over
//!   the asset's own identifiers. It also widens the asset to the IPs / MACs
//!   its own endpoints carry, exactly like the row read's widening, before any
//!   other card reads, so every card (and the later row read) starts from the
//!   widened predicate instead of re-reading a chunk for the delta.
//! - **timeline**: event counts by 28 window buckets (computed in the lake),
//!   class and log source; also the log-source list and first / last seen.
//! - **processes / network / dns / auth / files**: counts and sums grouped by
//!   exactly the fields the row assemblers read, plus the newest few auth and
//!   file events for the "recent" lists.
//!
//! Group rows carry their event count as [`CARD_WEIGHT`]; the row assemblers
//! in `lake_asset.rs` weigh every row by it, so a card and the same window's
//! rows fold to the same numbers through the same code.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde_json::Value;

use super::*;

/// Event count of a card group row.
pub(super) const CARD_WEIGHT: &str = "asset_n";
/// Timeline bucket of a card group row (0..[`TIMELINE_BUCKETS`]).
pub(super) const CARD_BUCKET: &str = "asset_bucket";
/// Oldest event time of a card group row.
pub(super) const CARD_FIRST_SEEN: &str = "asset_first";
pub(super) const CARD_PROCESS_HASH: &str = "asset_proc_hash";
pub(super) const CARD_ACTOR_HASH: &str = "asset_actor_hash";
pub(super) const CARD_PROCESS_CMD: &str = "asset_proc_cmd";
pub(super) const CARD_ACTOR_CMD: &str = "asset_actor_cmd";
pub(super) const CARD_BYTES_IN: &str = "asset_bytes_in";
pub(super) const CARD_BYTES_OUT: &str = "asset_bytes_out";
const CARD_PRODUCT: &str = "asset_product";
const CARD_VENDOR: &str = "asset_vendor";

/// Most groups one card reads (per predicate slice). NAN-3276: a card whose
/// groups do not fit keeps the groups it read -- the busiest ones, since a
/// grouped read is ordered by its count -- and is marked truncated (its
/// section's counts are lower bounds, see [`truncation_note`]). It never
/// falls back to the event rows: on a busy host that read is the one that
/// does not fit.
pub(super) const CARD_GROUP_CAP: usize = 10_000;
/// Newest events behind the auth / file "recent" lists.
pub(super) const CARD_RECENT: usize = 8;
/// Card reads one snapshot keeps in flight.
pub(super) const CARD_CONCURRENCY: usize = 4;

/// One dossier card's lake read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Section {
    Identity,
    Timeline,
    Processes,
    Network,
    Dns,
    Auth,
    AuthRecent,
    Files,
    FilesRecent,
    /// NAN-3291: the event-stream total and type / source facets over the
    /// whole window (not a dossier card; never in [`Section::CARDS`]).
    Counts,
    /// NAN-3291: the event-stream user facet over the whole window.
    CountUsers,
}

impl Section {
    /// Every card after the identity, in the order they are issued (the
    /// timeline first: it is the page's first paint after the identity).
    pub(super) const CARDS: [Section; 8] = [
        Section::Timeline,
        Section::Processes,
        Section::Network,
        Section::Auth,
        Section::Files,
        Section::Dns,
        Section::AuthRecent,
        Section::FilesRecent,
    ];

    /// The lake view name (request id prefix) of this card.
    pub(super) fn view(self) -> &'static str {
        match self {
            Section::Identity => "asset-card-identity",
            Section::Timeline => "asset-card-timeline",
            Section::Processes => "asset-card-processes",
            Section::Network => "asset-card-network",
            Section::Dns => "asset-card-dns",
            Section::Auth => "asset-card-auth",
            Section::AuthRecent => "asset-card-auth-recent",
            Section::Files => "asset-card-files",
            Section::FilesRecent => "asset-card-files-recent",
            Section::Counts => "asset-counts",
            Section::CountUsers => "asset-counts-users",
        }
    }

    /// The section's name in a dossier note.
    pub(super) fn label(self) -> &'static str {
        match self {
            Section::Identity => "identity",
            Section::Timeline => "timeline",
            Section::Processes => "processes",
            Section::Network => "network",
            Section::Dns => "dns",
            Section::Auth => "auth",
            Section::AuthRecent => "recent auth",
            Section::Files => "files",
            Section::FilesRecent => "recent files",
            Section::Counts => "event counts",
            Section::CountUsers => "user counts",
        }
    }

    /// A newest-first event page (projected) rather than a grouped stats.
    pub(super) fn is_page(self) -> bool {
        matches!(self, Section::AuthRecent | Section::FilesRecent)
    }

    fn limit(self) -> usize {
        if self.is_page() {
            CARD_RECENT
        } else {
            CARD_GROUP_CAP
        }
    }
}

/// One planned card read: run `query` once per predicate slice and
/// concatenate (slices are disjoint, so group weights add up exactly).
#[derive(Debug, Clone)]
pub(super) struct CardQuery {
    pub section: Section,
    pub queries: Vec<String>,
    pub limit: usize,
}

/// NAN-3408: the auth cards' term excluding OCSF Authentication Logoff.
const AUTH_NOT_LOGOFF: &str = "activity_id!=2";

const AUTH_RECENT_PROJECTION: &[&str] = &[
    "time",
    "metadata.uid",
    "class_uid",
    "status",
    "status_id",
    "auth_protocol",
    "logon_type",
    "unmapped.logon_type",
    "actor.user.name",
    "user.name",
    "src_endpoint.hostname",
    "src_endpoint.ip",
    "dst_endpoint.port",
    "unmapped.failure_reason",
    "unmapped.error_message",
];

const FILES_RECENT_PROJECTION: &[&str] = &[
    "time",
    "metadata.uid",
    "class_uid",
    "activity_name",
    "file.path",
    "file.name",
    "raw_data_size",
    "actor.process.name",
    "process.name",
];

/// A newest-first event page that projects exactly `fields` (requested with
/// `table_view`, like the Asset event page).
fn recent_page(filtered: &str, fields: &[&str]) -> String {
    format!(
        "{filtered} | eval {ASSET_PAGE_PROJECTION_ALIAS}=coalesce({})",
        fields
            .iter()
            .map(|field| format!("tostring({field})"))
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// The identity card over one predicate slice.
pub(super) fn identity_query(slice: &str) -> String {
    format!(
        "{slice} | stats count() as {CARD_WEIGHT}, max(time) as time, \
         last(metadata.product.name) as {CARD_PRODUCT}, \
         last(metadata.product.vendor_name) as {CARD_VENDOR} \
         by device.hostname, src_endpoint.hostname, src_endpoint.ip, src_endpoint.mac, \
         dst_endpoint.hostname, dst_endpoint.ip, dst_endpoint.mac, actor.user.name, user.name"
    )
}

/// The nPL of one card over one predicate slice. `window` is the dossier's
/// window: the timeline buckets are computed against it in the lake, with the
/// same arithmetic `lake_asset_timeline` applies to a row.
pub(super) fn card_query(section: Section, slice: &str, window: &TimeRange) -> String {
    match section {
        Section::Identity => identity_query(slice),
        Section::Timeline => {
            let start = window.start.timestamp();
            let seconds = (window.end.timestamp() - start).max(1);
            format!(
                "{slice} | eval {CARD_BUCKET}=floor((epoch(time)-{start})*{TIMELINE_BUCKETS}/{seconds}) \
                 | stats count() as {CARD_WEIGHT}, max(time) as time, min(time) as {CARD_FIRST_SEEN} \
                 by {CARD_BUCKET}, class_uid, metadata.log_source"
            )
        }
        Section::Processes => format!(
            "{slice} (process.name=* OR actor.process.name=*) \
             | stats count() as {CARD_WEIGHT}, max(time) as time, \
             last(process.file.hashes.value) as {CARD_PROCESS_HASH}, \
             last(actor.process.file.hashes.value) as {CARD_ACTOR_HASH}, \
             last(process.cmd_line) as {CARD_PROCESS_CMD}, \
             last(actor.process.cmd_line) as {CARD_ACTOR_CMD} \
             by process.name, actor.process.name, unmapped.signed"
        ),
        Section::Network => format!(
            "{slice} (class_uid=4001 OR class_uid=4003) \
             | stats count() as {CARD_WEIGHT}, sum(traffic.bytes_in) as {CARD_BYTES_IN}, \
             sum(traffic.bytes_out) as {CARD_BYTES_OUT} \
             by class_uid, dst_endpoint.hostname, query.hostname, dst_endpoint.ip"
        ),
        Section::Dns => format!(
            "{slice} class_uid=4003 | stats count() as {CARD_WEIGHT} \
             by class_uid, query.hostname, status, status_id, unmapped.status"
        ),
        // NAN-3408: logon attempts only. A Logoff (OCSF Authentication
        // activity_id 2, Windows 4634) is not a success and not a logon; on
        // the load-test tenant it was ~27% of the auth rows. `activity_id` is required on
        // every OCSF event, so `!=` (which drops nulls) loses no logons.
        Section::Auth => format!(
            "{slice} class_uid=3002 {AUTH_NOT_LOGOFF} | stats count() as {CARD_WEIGHT} \
             by class_uid, status, status_id, auth_protocol, logon_type, unmapped.logon_type, dst_endpoint.port"
        ),
        Section::Files => format!(
            "{slice} class_uid=1001 | stats count() as {CARD_WEIGHT} \
             by class_uid, activity_name, file.path, file.name"
        ),
        Section::AuthRecent => {
            recent_page(&format!("{slice} class_uid=3002 {AUTH_NOT_LOGOFF}"), AUTH_RECENT_PROJECTION)
        }
        Section::FilesRecent => {
            recent_page(&format!("{slice} class_uid=1001"), FILES_RECENT_PROJECTION)
        }
        Section::Counts => count_query(slice),
        Section::CountUsers => count_users_query(slice),
    }
}

/// NAN-3291: the event-stream total plus the type and source facets over one
/// predicate slice. Grouped by `(source, class, auth failure)` only, so the
/// groups stay a few dozen whatever the asset's volume: the total and these
/// facets are exact from one bounded aggregate, no rows read. Labels fold
/// through `asset_facets_from_grouped_rows` like the filtered summary.
pub(super) fn count_query(slice: &str) -> String {
    format!(
        "{slice} | eval asset_auth_failure=if(class_uid=3002 AND {LAKE_STATUS_FAILURE_NPL}, 1, 0) \
         | stats count() as event_count by metadata.log_source, class_uid, asset_auth_failure"
    )
}

/// NAN-3291: the event-stream user facet over one predicate slice (kept
/// apart from [`count_query`] so a server with thousands of users never
/// makes the total inexact).
pub(super) fn count_users_query(slice: &str) -> String {
    format!(
        "{slice} | eval asset_user=coalesce(actor.user.name,user.name) \
         | where asset_user!=\"\" | stats count() as event_count by asset_user"
    )
}

/// NAN-3291: the two count reads, after the identity card, over the widened
/// predicate's slices.
pub(super) fn count_plan(slices: &[String]) -> Vec<CardQuery> {
    [Section::Counts, Section::CountUsers]
        .into_iter()
        .map(|section| CardQuery {
            section,
            queries: slices
                .iter()
                .map(|slice| {
                    if section == Section::Counts {
                        count_query(slice)
                    } else {
                        count_users_query(slice)
                    }
                })
                .collect(),
            limit: section.limit(),
        })
        .collect()
}

/// The card reads (after the identity card) over the widened predicate's
/// slices.
pub(super) fn card_plan(slices: &[String], window: &TimeRange) -> Vec<CardQuery> {
    Section::CARDS
        .iter()
        .map(|section| CardQuery {
            section: *section,
            queries: slices
                .iter()
                .map(|slice| card_query(*section, slice, window))
                .collect(),
            limit: section.limit(),
        })
        .collect()
}

/// NAN-3276: the dossier note for cards that reached [`CARD_GROUP_CAP`].
pub(super) fn truncation_note(truncated: &BTreeSet<Section>) -> Option<String> {
    (!truncated.is_empty()).then(|| {
        format!(
            "{} {} the busiest {CARD_GROUP_CAP} groups only; {} counts are lower bounds",
            truncated
                .iter()
                .map(|section| section.label())
                .collect::<Vec<_>>()
                .join(", "),
            if truncated.len() == 1 {
                "shows"
            } else {
                "show"
            },
            if truncated.len() == 1 { "its" } else { "their" },
        )
    })
}

/// NAN-3276: one card read of a durable Asset dossier: run every query (one
/// per predicate slice, disjoint) with `limit` and hand the rows, with
/// whether every query stayed under `limit`, to [`LakeAssetCards::insert`].
#[derive(Debug, Clone)]
pub struct LakeAssetCardRead {
    section: Section,
    /// The lake view name (request id suffix) of this card.
    pub view: &'static str,
    pub queries: Vec<String>,
    pub limit: usize,
}

/// NAN-3276: the dossier cards a durable Asset dossier read, folded by the
/// same code as the interactive dossier's cards. The durable lane reads the
/// same bounded aggregates (group rows, never event rows), so its memory is
/// bounded by [`CARD_GROUP_CAP`] per card and slice whatever the host's event
/// volume.
#[derive(Debug, Default)]
pub struct LakeAssetCards {
    cards: BTreeMap<Section, Arc<Vec<Value>>>,
    truncated: BTreeSet<Section>,
}

impl LakeAssetCards {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one card's rows (every slice's, concatenated). `exact`: no
    /// slice's grouped read reached the card's limit.
    pub fn insert(&mut self, read: &LakeAssetCardRead, rows: Vec<Value>, exact: bool) {
        let rows = if read.section.is_page() {
            let mut rows = newest_first(rows);
            rows.truncate(CARD_RECENT);
            rows
        } else {
            if !exact {
                self.truncated.insert(read.section);
            }
            rows
        };
        self.cards.insert(read.section, Arc::new(rows));
    }

    /// The artifacts whose prevalence the dossier's rarity reads.
    pub fn artifacts(&self) -> Vec<String> {
        card_artifacts(&self.cards)
    }

    /// The dossier over the cards read, with `prevalence` (artifact ->
    /// `(host_count, is_rare, score)`).
    pub fn dossier(
        &self,
        window: &TimeRange,
        prevalence: &BTreeMap<String, (u64, bool, u8)>,
    ) -> AssetDossier {
        let mut dossier = AssetDossier::default();
        overlay_cards(&mut dossier, &self.cards, window, prevalence);
        if let Some(note) = truncation_note(&self.truncated) {
            dossier.progress = Some(ProductViewProgress {
                complete: true,
                covered_start: Some(
                    window
                        .start
                        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                ),
                covered_end: Some(
                    window
                        .end
                        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                ),
                retry_after_ms: None,
                note: Some(note),
            });
        }
        dossier
    }
}

/// NAN-3276: every card read of an Asset dossier (identity first) over the
/// asset's predicate slices.
pub(super) fn dossier_card_reads(slices: &[String], window: &TimeRange) -> Vec<LakeAssetCardRead> {
    let identity = LakeAssetCardRead {
        section: Section::Identity,
        view: Section::Identity.view(),
        queries: slices.iter().map(|slice| identity_query(slice)).collect(),
        limit: CARD_GROUP_CAP,
    };
    std::iter::once(identity)
        .chain(
            card_plan(slices, window)
                .into_iter()
                .map(|card| LakeAssetCardRead {
                    section: card.section,
                    view: card.section.view(),
                    queries: card.queries,
                    limit: card.limit,
                }),
        )
        .collect()
}

/// Hash values of a card alias: a `last(<hash array>)` comes back as an
/// array, a scalar rendering as a string.
pub(super) fn card_hash_values(row: &Value, alias: &str) -> Vec<String> {
    match row.get(alias) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect(),
        Some(Value::String(value)) if !value.is_empty() && !value.starts_with('[') => {
            vec![value.clone()]
        }
        Some(Value::String(value)) if value.starts_with('[') => {
            serde_json::from_str::<Vec<String>>(value)
                .unwrap_or_default()
                .into_iter()
                .filter(|value| !value.is_empty())
                .collect()
        }
        _ => Vec::new(),
    }
}

/// Group rows newest first (by their `max(time)`), the order the row
/// assemblers' "latest value" reads expect.
pub(super) fn newest_first(mut rows: Vec<Value>) -> Vec<Value> {
    rows.sort_by(|left, right| lake_string(right, "time").cmp(&lake_string(left, "time")));
    rows
}

/// The identity card's rows as the row assemblers read them: the product
/// aliases back under their OCSF paths.
pub(super) fn identity_rows(rows: &[Value]) -> Vec<Value> {
    newest_first(
        rows.iter()
            .cloned()
            .map(|mut row| {
                if let Value::Object(object) = &mut row {
                    for (alias, path) in [
                        (CARD_PRODUCT, "metadata.product.name"),
                        (CARD_VENDOR, "metadata.product.vendor_name"),
                    ] {
                        if let Some(value) = object.remove(alias) {
                            object.insert(path.to_string(), value);
                        }
                    }
                }
                row
            })
            .collect(),
    )
}

/// The artifacts whose prevalence the cards' rarity reads: process hashes and
/// destination / query domains, keyed exactly as the row path keys them.
pub(super) fn card_artifacts(cards: &BTreeMap<Section, Arc<Vec<Value>>>) -> Vec<String> {
    let mut out = BTreeSet::new();
    if let Some(rows) = cards.get(&Section::Processes) {
        out.extend(
            rows.iter()
                .filter_map(process_observation)
                .filter_map(|(_, hash, _)| hash),
        );
    }
    for section in [Section::Network, Section::Dns] {
        if let Some(rows) = cards.get(&section) {
            for row in rows.iter() {
                for path in ["dst_endpoint.hostname", "query.hostname"] {
                    if let Some(domain) =
                        lake_string(row, path).filter(|value| is_lake_domain_artifact(value))
                    {
                        out.insert(domain.trim().to_ascii_lowercase());
                    }
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Lay every card that has been read over `dossier` (built from the snapshot
/// rows read so far). A card that is missing (not read yet, or failed) leaves
/// that section as the rows built it.
pub(super) fn overlay_cards(
    dossier: &mut AssetDossier,
    cards: &BTreeMap<Section, Arc<Vec<Value>>>,
    window: &TimeRange,
    prevalence: &BTreeMap<String, (u64, bool, u8)>,
) {
    if let Some(rows) = cards.get(&Section::Identity) {
        let identity = lake_asset_identity(&identity_rows(rows));
        dossier.identity.hostname = identity.hostname.or(dossier.identity.hostname.take());
        dossier.identity.ip = identity.ip.or(dossier.identity.ip.take());
        dossier.identity.mac = identity.mac.or(dossier.identity.mac.take());
        dossier.identity.user = identity.user.or(dossier.identity.user.take());
        dossier.identity.vendor_product = identity
            .vendor_product
            .or(dossier.identity.vendor_product.take());
        dossier.identity.domain = identity.domain.or(dossier.identity.domain.take());
    }
    if let Some(rows) = cards.get(&Section::Timeline) {
        let rows = newest_first(rows.as_ref().clone());
        dossier.timeline = lake_asset_timeline(&rows, window);
        let identity = lake_asset_identity(&rows);
        dossier.identity.log_sources = identity.log_sources;
        dossier.identity.first_seen_in_range = identity.first_seen_in_range;
        dossier.identity.last_seen_in_range = identity.last_seen_in_range;
    }
    if let Some(rows) = cards.get(&Section::Processes) {
        dossier.processes = lake_asset_processes(&newest_first(rows.as_ref().clone()), prevalence);
    }
    if let Some(rows) = cards.get(&Section::Network) {
        dossier.network = lake_asset_network(rows, prevalence);
    }
    if let Some(rows) = cards.get(&Section::Dns) {
        dossier.dns = lake_asset_dns(rows);
    }
    if let Some(rows) = cards.get(&Section::Auth) {
        let recent = std::mem::take(&mut dossier.auth.recent);
        dossier.auth = lake_asset_auth(rows);
        dossier.auth.recent = match cards.get(&Section::AuthRecent) {
            Some(page) => lake_asset_auth(page).recent,
            None => recent,
        };
    } else if let Some(page) = cards.get(&Section::AuthRecent) {
        dossier.auth.recent = lake_asset_auth(page).recent;
    }
    if let Some(rows) = cards.get(&Section::Files) {
        let recent = std::mem::take(&mut dossier.files.recent);
        dossier.files = lake_asset_files(rows);
        dossier.files.recent = match cards.get(&Section::FilesRecent) {
            Some(page) => lake_asset_files(page).recent,
            None => recent,
        };
    } else if let Some(page) = cards.get(&Section::FilesRecent) {
        dossier.files.recent = lake_asset_files(page).recent;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn window() -> TimeRange {
        let start = chrono::DateTime::parse_from_rfc3339("2026-10-07T22:13:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        TimeRange::new(start, start + chrono::Duration::hours(1))
    }

    #[test]
    fn plan_reads_every_card_per_slice_and_projects_only_card_columns() {
        let slices = vec![
            "(device.hostname=\"h\")".to_string(),
            "(b AND NOT (a))".to_string(),
        ];
        let plan = card_plan(&slices, &window());
        let sections = plan.iter().map(|card| card.section).collect::<Vec<_>>();
        assert_eq!(sections, Section::CARDS.to_vec());
        assert_eq!(sections[0], Section::Timeline, "timeline paints first");
        for card in &plan {
            assert_eq!(card.queries.len(), 2, "{:?}", card.section);
            for (query, slice) in card.queries.iter().zip(&slices) {
                assert!(query.starts_with(slice.as_str()), "{query}");
                if matches!(card.section, Section::Auth | Section::AuthRecent) {
                    assert!(query.contains("class_uid=3002 activity_id!=2"), "{query}");
                }
                if card.section.is_page() {
                    assert_eq!(card.limit, CARD_RECENT);
                    assert!(query.contains(ASSET_PAGE_PROJECTION_ALIAS), "{query}");
                } else {
                    assert_eq!(card.limit, CARD_GROUP_CAP);
                    // Aggregated in the lake: only group rows come back,
                    // never the wide event projection.
                    assert!(
                        query.contains(&format!("| stats count() as {CARD_WEIGHT}")),
                        "{query}"
                    );
                    assert!(!query.contains("| table"), "{query}");
                }
            }
        }
        // A class-scoped card leads with its class conjunct, which the lake
        // compiler turns into a whole-file class hint.
        let auth = &plan
            .iter()
            .find(|card| card.section == Section::Auth)
            .unwrap()
            .queries[0];
        assert!(auth.contains(") class_uid=3002 activity_id!=2 |"), "{auth}");
        // The timeline buckets are computed in the lake against the window.
        let timeline = &plan[0].queries[0];
        let start = window().start.timestamp();
        assert!(
            timeline.contains(&format!("floor((epoch(time)-{start})*28/3600)")),
            "{timeline}"
        );
    }

    #[test]
    fn group_rows_fold_like_the_events_they_count() {
        let window = window();
        let prevalence = BTreeMap::from([
            ("aaaa".to_string(), (40, false, 90)),
            ("evil.example".to_string(), (1, true, 2)),
        ]);
        let events = vec![
            json!({"time": "2026-10-07 22:20:00.000000", "class_uid": 1007, "metadata.log_source": "sysmon",
                   "process.name": "cmd.exe", "process.file.hashes.value": ["AAAA"], "process.cmd_line": "cmd /c new",
                   "actor.process.name": "winword.exe", "unmapped.signed": false}),
            json!({"time": "2026-10-07 22:15:00.000000", "class_uid": 1007, "metadata.log_source": "sysmon",
                   "process.name": "cmd.exe", "process.file.hashes.value": ["AAAA"], "process.cmd_line": "cmd /c old",
                   "actor.process.name": "winword.exe", "unmapped.signed": false}),
            json!({"time": "2026-10-07 22:30:00.000000", "class_uid": 4001, "metadata.log_source": "zeek",
                   "dst_endpoint.hostname": "evil.example", "dst_endpoint.ip": "203.0.113.9",
                   "traffic.bytes_in": 10, "traffic.bytes_out": 100}),
            json!({"time": "2026-10-07 22:31:00.000000", "class_uid": 4001, "metadata.log_source": "zeek",
                   "dst_endpoint.hostname": "evil.example", "dst_endpoint.ip": "203.0.113.9",
                   "traffic.bytes_in": 5, "traffic.bytes_out": 50}),
            json!({"time": "2026-10-07 22:32:00.000000", "class_uid": 3002, "metadata.log_source": "winsec",
                   "status": "Failure", "auth_protocol": "NTLM", "logon_type": "Network", "dst_endpoint.port": 445}),
        ];
        let from_rows = SearchService::assemble_lake_asset_dossier_from(
            &newest_first(events.clone()),
            &window,
            &prevalence,
        );
        let start = window.start.timestamp();
        let bucket = |time: &str| {
            let at = parse_lake_asset_time(time).unwrap().timestamp();
            ((at - start) * 28 / 3600) as f64
        };
        let cards = BTreeMap::from([
            (
                Section::Timeline,
                Arc::new(vec![
                    json!({CARD_BUCKET: bucket("2026-10-07 22:20:00"), "class_uid": 1007, "metadata.log_source": "sysmon",
                       CARD_WEIGHT: 1, "time": "2026-10-07 22:20:00.000000", CARD_FIRST_SEEN: "2026-10-07 22:20:00.000000"}),
                    json!({CARD_BUCKET: bucket("2026-10-07 22:15:00"), "class_uid": 1007, "metadata.log_source": "sysmon",
                       CARD_WEIGHT: 1, "time": "2026-10-07 22:15:00.000000", CARD_FIRST_SEEN: "2026-10-07 22:15:00.000000"}),
                    json!({CARD_BUCKET: bucket("2026-10-07 22:30:00"), "class_uid": 4001, "metadata.log_source": "zeek",
                       CARD_WEIGHT: 1, "time": "2026-10-07 22:30:00.000000", CARD_FIRST_SEEN: "2026-10-07 22:30:00.000000"}),
                    json!({CARD_BUCKET: bucket("2026-10-07 22:31:00"), "class_uid": 4001, "metadata.log_source": "zeek",
                       CARD_WEIGHT: "1", "time": "2026-10-07 22:31:00.000000", CARD_FIRST_SEEN: "2026-10-07 22:31:00.000000"}),
                    json!({CARD_BUCKET: bucket("2026-10-07 22:32:00"), "class_uid": 3002, "metadata.log_source": "winsec",
                       CARD_WEIGHT: 1, "time": "2026-10-07 22:32:00.000000", CARD_FIRST_SEEN: "2026-10-07 22:32:00.000000"}),
                ]),
            ),
            (
                Section::Processes,
                Arc::new(vec![json!({
                    "process.name": "cmd.exe", "actor.process.name": "winword.exe", "unmapped.signed": "false",
                    CARD_WEIGHT: 2, "time": "2026-10-07 22:20:00.000000",
                    CARD_PROCESS_HASH: ["AAAA"], CARD_PROCESS_CMD: "cmd /c new",
                })]),
            ),
            (
                Section::Network,
                Arc::new(vec![json!({
                    "class_uid": 4001, "dst_endpoint.hostname": "evil.example", "dst_endpoint.ip": "203.0.113.9",
                    CARD_WEIGHT: "2", CARD_BYTES_IN: 15, CARD_BYTES_OUT: 150,
                })]),
            ),
            (Section::Dns, Arc::new(Vec::new())),
            (
                Section::Auth,
                Arc::new(vec![json!({
                    "class_uid": 3002, "status": "Failure", "auth_protocol": "NTLM", "logon_type": "Network", "dst_endpoint.port": 445, CARD_WEIGHT: 1,
                })]),
            ),
            (Section::AuthRecent, Arc::new(vec![events[4].clone()])),
            (Section::Files, Arc::new(Vec::new())),
            (Section::FilesRecent, Arc::new(Vec::new())),
        ]);
        let mut from_cards = AssetDossier::default();
        overlay_cards(&mut from_cards, &cards, &window, &prevalence);
        assert_eq!(
            serde_json::to_value(&from_cards.timeline).unwrap(),
            serde_json::to_value(&from_rows.timeline).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&from_cards.processes).unwrap(),
            serde_json::to_value(&from_rows.processes).unwrap()
        );
        assert_eq!(from_cards.processes.unsigned, 2);
        assert_eq!(from_cards.processes.from_office, 2);
        assert_eq!(
            serde_json::to_value(&from_cards.network).unwrap(),
            serde_json::to_value(&from_rows.network).unwrap()
        );
        assert_eq!(from_cards.network.new_domains, 1);
        assert_eq!(
            serde_json::to_value(&from_cards.auth).unwrap(),
            serde_json::to_value(&from_rows.auth).unwrap()
        );
        // NAN-3408: the NETWORK tile counts the logon TYPE, not the protocol.
        assert_eq!(from_cards.auth.network, 1);
        assert_eq!(from_cards.auth.interactive, 0);
        assert_eq!(from_cards.auth.recent[0].auth_type, "NTLM");
        assert_eq!(
            serde_json::to_value(&from_cards.identity.log_sources).unwrap(),
            serde_json::to_value(&from_rows.identity.log_sources).unwrap()
        );
        assert_eq!(
            from_cards.identity.first_seen_in_range,
            from_rows.identity.first_seen_in_range
        );
        assert_eq!(
            from_cards.identity.last_seen_in_range,
            from_rows.identity.last_seen_in_range
        );
        assert_eq!(
            card_artifacts(&cards),
            vec!["aaaa".to_string(), "evil.example".to_string()]
        );
    }

    #[test]
    fn identity_card_names_the_asset_from_its_newest_group() {
        let rows = vec![
            json!({"time": "2026-10-07 22:00:00.000000", "device.hostname": "old-name", CARD_WEIGHT: 3}),
            json!({"time": "2026-10-07 22:59:00.000000", "device.hostname": "ws-it-083.corp.local",
                   "src_endpoint.ip": "10.1.2.3", "actor.user.name": "alice", CARD_PRODUCT: "Sysmon", CARD_WEIGHT: 1}),
        ];
        let cards = BTreeMap::from([(Section::Identity, Arc::new(rows))]);
        let mut dossier = AssetDossier::default();
        overlay_cards(&mut dossier, &cards, &window(), &BTreeMap::new());
        assert_eq!(
            dossier.identity.hostname.as_deref(),
            Some("ws-it-083.corp.local")
        );
        assert_eq!(dossier.identity.ip.as_deref(), Some("10.1.2.3"));
        assert_eq!(dossier.identity.user.as_deref(), Some("alice"));
        assert_eq!(dossier.identity.vendor_product.as_deref(), Some("Sysmon"));
        assert_eq!(dossier.identity.domain.as_deref(), Some("corp.local"));
    }
}
