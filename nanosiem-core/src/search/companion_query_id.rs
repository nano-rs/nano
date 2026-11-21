//! Derived ClickHouse query ids for the companion queries one search fans out
//! (NAN-1428, NAN-5723).
//!
//! A search runs its data query under the request's `query_id` and each
//! companion (count, histogram, field stats, ...) under `{query_id}-<suffix>`.
//! Cancel kills the data query plus every derived id, matched EXACTLY (never
//! `LIKE '{id}%'`: client request ids can contain `%`/`_`).
//!
//! Every derived id is built here, from [`CompanionQuery`], and the kill set
//! ([`all_query_ids`]) is built from [`CompanionQuery::ALL`]. A new companion
//! is a new variant: `companion_query_id_tests` fails if `ALL` misses a
//! declared variant or if a derived id is built anywhere else with `format!`.
//!
//! Client-chosen request ids are checked by [`validate_client_request_id`] so
//! no two valid ids can share a derived id: cancel authorizes on the raw id,
//! so a shared derived id would let one user kill another's query.

/// One companion query a search can run beside its data query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CompanionQuery {
    /// The parallel `count(*)` of a paginated / streaming search.
    Count,
    /// The timeline histogram.
    Hist,
    /// Sidebar field stats.
    Fstats,
    /// The aggregation fallback count when a page lands past the final group
    /// (NAN-4915).
    AggregateCount,
    /// The sidebar's spill-bucket field inventory (NAN-5485).
    InvSpill,
    /// The sidebar's extended-bucket field inventory (NAN-5485).
    InvExtended,
    /// The cost guard's row estimate (NAN-5635).
    Guard,
    /// The `enrich=true` page rescue probe (NAN-5718).
    PrevalenceRescue,
    /// The enrich-only prevalence pushdown's base count (NAN-5660).
    BaseCount,
    /// Streaming daily chunks with an even index. Chunks run one after
    /// another, so two alternating ids cover them all and a chunk never
    /// reuses the id of the chunk that just finished.
    StreamChunkEven,
    /// Streaming daily chunks with an odd index (see `StreamChunkEven`).
    StreamChunkOdd,
    /// The prevalence filter rescue probe over the hash summary (NAN-1705).
    RescueProbeHash,
    /// The prevalence filter rescue probe over the domain summary (NAN-1705).
    RescueProbeDomain,
    /// The prevalence filter rescue probe over the IP summary (NAN-1705).
    RescueProbeIp,
    /// The in-memory enrichment's summary re-check of dict misses (NAN-5718).
    PrevalenceRecheck,
}

impl CompanionQuery {
    /// Every companion, in kill-set order. `all_lists_every_variant` checks it
    /// against the declared variants.
    pub(crate) const ALL: [CompanionQuery; 15] = [
        CompanionQuery::Count,
        CompanionQuery::Hist,
        CompanionQuery::Fstats,
        CompanionQuery::AggregateCount,
        CompanionQuery::InvSpill,
        CompanionQuery::InvExtended,
        CompanionQuery::Guard,
        CompanionQuery::PrevalenceRescue,
        CompanionQuery::BaseCount,
        CompanionQuery::StreamChunkEven,
        CompanionQuery::StreamChunkOdd,
        CompanionQuery::RescueProbeHash,
        CompanionQuery::RescueProbeDomain,
        CompanionQuery::RescueProbeIp,
        CompanionQuery::PrevalenceRecheck,
    ];

    /// The fixed id suffix. Changing one breaks kill coverage for searches
    /// in flight during a rolling deploy.
    pub(crate) const fn suffix(self) -> &'static str {
        match self {
            CompanionQuery::Count => "count",
            CompanionQuery::Hist => "hist",
            CompanionQuery::Fstats => "fstats",
            CompanionQuery::AggregateCount => "aggregate-count",
            CompanionQuery::InvSpill => "inv-spill",
            CompanionQuery::InvExtended => "inv-extended",
            CompanionQuery::Guard => "guard",
            CompanionQuery::PrevalenceRescue => "prevalence-rescue",
            CompanionQuery::BaseCount => "base-count",
            CompanionQuery::StreamChunkEven => "chunk-0",
            CompanionQuery::StreamChunkOdd => "chunk-1",
            CompanionQuery::RescueProbeHash => "rescue-probe-hash",
            CompanionQuery::RescueProbeDomain => "rescue-probe-domain",
            CompanionQuery::RescueProbeIp => "rescue-probe-ip",
            CompanionQuery::PrevalenceRecheck => "prevalence-recheck",
        }
    }

    /// This companion's ClickHouse query id for search `query_id`.
    pub(crate) fn query_id(self, query_id: &str) -> String {
        format!("{query_id}-{}", self.suffix())
    }

    /// The companion for streaming chunk `index`.
    pub(crate) const fn stream_chunk(index: usize) -> Self {
        if index % 2 == 0 {
            CompanionQuery::StreamChunkEven
        } else {
            CompanionQuery::StreamChunkOdd
        }
    }
}

/// Derived ids of every companion of search `query_id`, in
/// [`CompanionQuery::ALL`] order.
pub(crate) fn companion_query_ids(query_id: &str) -> Vec<String> {
    CompanionQuery::ALL
        .iter()
        .map(|c| c.query_id(query_id))
        .collect()
}

/// The full kill set for one search: the data query id plus every derived
/// companion id (NAN-1428).
pub fn all_query_ids(query_id: &str) -> Vec<String> {
    let mut ids = Vec::with_capacity(CompanionQuery::ALL.len() + 1);
    ids.push(query_id.to_string());
    ids.extend(companion_query_ids(query_id));
    ids
}

/// Longest client request id accepted.
pub const MAX_CLIENT_REQUEST_ID_LEN: usize = 128;

/// Why a client request id was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RequestIdError {
    #[error("request_id must be 1 to 128 characters")]
    Length,
    #[error("request_id may only contain letters, digits, '.', '_', ':' and '-'")]
    Charset,
    #[error("request_id must not end in a reserved companion-query suffix")]
    ReservedSuffix,
}

/// Every hyphen-separated tail a client id must not end with: each companion
/// suffix and each of its proper hyphen prefixes (`aggregate` of
/// `aggregate-count`).
///
/// This is exactly what keeps derived ids unique. `A-s1 == V-s2` with
/// `A != V` needs one suffix to end in `-` + the other, so `V == A-p` for a
/// hyphen prefix `p` of `s1`; and `V == A-s1` needs `V` to end in `-s1`.
/// Refusing ids that end in `-s` or `-p` rules out both.
fn reserved_tails() -> impl Iterator<Item = &'static str> {
    CompanionQuery::ALL.iter().flat_map(|c| {
        let suffix = c.suffix();
        suffix
            .match_indices('-')
            .map(move |(i, _)| &suffix[..i])
            .chain(std::iter::once(suffix))
    })
}

/// NAN-5723: refuse a client-chosen request id that could share a derived
/// ClickHouse query id with another valid id. Cancel authorizes on the raw
/// id and then kills [`all_query_ids`], so a collision would let one
/// principal kill another's query. Server-generated UUIDs always pass.
pub fn validate_client_request_id(id: &str) -> Result<(), RequestIdError> {
    if id.is_empty() || id.len() > MAX_CLIENT_REQUEST_ID_LEN {
        return Err(RequestIdError::Length);
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        return Err(RequestIdError::Charset);
    }
    let lower = id.to_ascii_lowercase();
    if reserved_tails().any(|tail| {
        lower.len() > tail.len()
            && lower.ends_with(tail)
            && lower.as_bytes()[lower.len() - tail.len() - 1] == b'-'
    }) {
        return Err(RequestIdError::ReservedSuffix);
    }
    Ok(())
}

#[cfg(test)]
#[path = "companion_query_id_tests.rs"]
mod companion_query_id_tests;
