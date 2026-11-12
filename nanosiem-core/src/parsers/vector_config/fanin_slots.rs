// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable fan-in slots (NAN-5132).
//!
//! `db_parsers_combined`, `db_parser_health` and the disk-buffered
//! `clickhouse_ocsf_logs` sink used to list every parser in `inputs`. Adding
//! or removing one source therefore changed all three, and Vector rebuilds a
//! changed component by re-walking the schema of every upstream remap: the
//! reload stalled all ingest for O(N) (18.9 s at 20 sources, 71.6 s at 50;
//! vector-nano `topology/running.rs`, `topology/schema.rs`). Rebuilding the
//! disk-buffered sink on reload is also the wedge in
//! reference_vector_reload_wedges_on_disk_buffered_sink.
//!
//! Instead every fan-in reads a FIXED set of slot filters. A slot is a
//! pass-through `filter` whose input is one parser's output, or the parked
//! never-matching filter. Adding a source changes only its own chain, the
//! router and its slots; the fan-ins and the sink keep byte-identical configs
//! and are not rebuilt.
//!
//! * Capacity `K` is a power of two, at least [`MIN_SLOTS`], with headroom
//!   (`n * 5/4`). Crossing a size (16 → 32 …) changes the fan-ins once.
//! * A parser's slot is a pure function of the enabled set: parsers in
//!   `(created_at, id)` order each take `id mod K`, probing linearly. A new
//!   (newest) source never moves an existing one; removing one can move only
//!   a later source that had probed past it. Every API replica renders the
//!   same assignment from the same database rows.
//! * Slot ids contain `-`, which [`crate::vector_naming::safe_name`] never
//!   produces, so they cannot collide with a parser's components.

use super::VectorConfigManager;
use crate::parsers::types::Parser;

/// Are stable fan-in slots on? Off by default; `VECTOR_FANIN_SLOTS=on|true|1`
/// turns them on. Off, the fan-ins and the OCSF sink list every parser (the
/// pre-NAN-5132 shape).
///
/// Opt-in for installs that add or remove sources often: adding one source
/// then leaves the fan-ins and the disk-buffered OCSF sink untouched, and
/// the reload stall drops (15.7 s to 2.2 s at 20 sources). The price is
/// paid all the time: every parser event takes one more filter hop per
/// family (2 under UDM, 3 under OCSF), and the slot components exist whether
/// used or not (3·K under OCSF).
///
/// Measured on the shipped ghcr.io/nano-rs/vector:0.61.0-nano.8-debian
/// (2 CPU, OCSF parser set, 1M-event burst through every routed parser,
/// slots on vs off): idle RSS +11 MiB at 20 sources and +10 MiB at 50;
/// burst peak +15 MiB at 20 and +6 to +24 MiB at 50; Vector CPU +12 to +15 %
/// at 20 and about +6 % at 50. Up to ~5 % of the 512 MiB compose default
/// Vector limit, plus the CPU, on every event, so it stays opt-in.
///
/// Every API and jobs replica must render with the same value, or their
/// renders disagree. The chart (`vector.faninSlots`) and the compose files
/// (`x-nano-vector-render-env`) set it in one place for all of them.
pub fn enabled() -> bool {
    #[cfg(test)]
    if let Some(forced) = FORCED.with(|f| f.get()) {
        return forced;
    }
    matches!(
        std::env::var("VECTOR_FANIN_SLOTS")
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref(),
        Ok("on") | Ok("true") | Ok("1")
    )
}

#[cfg(test)]
thread_local! {
    static FORCED: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Tests only: force [`enabled`] on this thread (env reads race across
/// parallel tests).
#[cfg(test)]
pub(crate) fn force_for_test(on: Option<bool>) {
    FORCED.with(|f| f.set(on));
}

/// Smallest slot capacity.
pub(super) const MIN_SLOTS: usize = 16;
/// The never-matching filter a free slot reads.
pub(super) const PARKED: &str = "nano-slot-parked";
/// The always-present component the parked filter reads.
const PARKED_UPSTREAM: &str = "prepare_output";

/// Slot families. Each fan-in reads one or two of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Family {
    /// `<p>_output`, unsampled: parser health.
    Out,
    /// `<p>_sample` or `<p>_output`: the persisted (combined) stream.
    Kept,
    /// `<p>_ocsf_prepare`: OCSF health and the OCSF sink.
    Ocsf,
}

impl Family {
    fn tag(self) -> &'static str {
        match self {
            Self::Out => "out",
            Self::Kept => "kept",
            Self::Ocsf => "ocsf",
        }
    }

    pub(super) fn input_for(self, parser: &Parser) -> String {
        let safe = VectorConfigManager::safe_name(&parser.name);
        match self {
            Self::Out => format!("{safe}_output"),
            Self::Kept => {
                let sampled = parser.sampling_ratio.map(|r| r > 0.0 && r < 1.0).unwrap_or(false);
                if sampled {
                    format!("{safe}_sample")
                } else {
                    format!("{safe}_output")
                }
            }
            Self::Ocsf => format!("{safe}_ocsf_prepare"),
        }
    }
}

/// Component id of slot `index` in `family`.
pub(super) fn slot_id(family: Family, index: usize) -> String {
    format!("nano-slot-{}-{index:03}", family.tag())
}

/// Slot capacity for `n` parsers.
pub(super) fn capacity(n: usize) -> usize {
    let want = (n * 5).div_ceil(4);
    want.next_power_of_two().max(MIN_SLOTS)
}

/// The parsers that occupy slots: enabled log parsers (the fan-ins' set).
fn slotted(parsers: &[Parser]) -> Vec<&Parser> {
    let mut v: Vec<&Parser> = parsers
        .iter()
        .filter(|p| p.enabled && p.kind != "enrichment")
        .collect();
    v.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    v
}

/// The slot table: `K` entries, each a parser or free.
pub(super) fn assign(parsers: &[Parser]) -> Vec<Option<&Parser>> {
    let ordered = slotted(parsers);
    let k = capacity(ordered.len());
    let mut table: Vec<Option<&Parser>> = vec![None; k];
    for parser in ordered {
        let mut index = (parser.id.as_u128() % k as u128) as usize;
        while table[index].is_some() {
            index = (index + 1) % k;
        }
        table[index] = Some(parser);
    }
    table
}

/// The slot filters of `families` plus the parked filter, as TOML.
pub(super) fn slots_toml(table: &[Option<&Parser>], families: &[Family]) -> String {
    let mut out = String::from(
        "# NAN-5132: stable fan-in slots. Fan-ins read these fixed filters, so adding\n\
         # or removing a source rewires one slot instead of rebuilding every fan-in.\n",
    );
    out.push_str(&format!(
        "[transforms.{PARKED}]\ntype = \"filter\"\ninputs = [\"{PARKED_UPSTREAM}\"]\ncondition = \"false\"\n\n"
    ));
    for family in families {
        for (index, entry) in table.iter().enumerate() {
            let input = entry.map(|p| family.input_for(p)).unwrap_or_else(|| PARKED.to_string());
            out.push_str(&format!(
                "[transforms.{id}]\ntype = \"filter\"\ninputs = [\"{input}\"]\ncondition = \"true\"\n\n",
                id = slot_id(*family, index),
            ));
        }
    }
    out
}

/// A fan-in's `inputs` entries (quoted) for `families`.
pub(super) fn fanin_inputs(k: usize, families: &[Family]) -> Vec<String> {
    families
        .iter()
        .flat_map(|family| (0..k).map(move |i| format!("\"{}\"", slot_id(*family, i))))
        .collect()
}

/// Test helper: expand a component's `inputs` through slot filters to the
/// parser components they carry (parked slots dropped), over parsed docs.
#[cfg(test)]
pub(crate) fn resolved_inputs(docs: &[&str], component: &str) -> Vec<String> {
    let mut components: std::collections::BTreeMap<String, toml::Value> =
        std::collections::BTreeMap::new();
    for doc in docs {
        let value: toml::Value = toml::from_str(&without_env(doc)).expect("valid TOML");
        for kind in ["transforms", "sinks"] {
            if let Some(table) = value.get(kind).and_then(|t| t.as_table()) {
                for (name, def) in table {
                    components.insert(name.clone(), def.clone());
                }
            }
        }
    }
    let inputs_of = |name: &str| -> Vec<String> {
        components
            .get(name)
            .and_then(|d| d.get("inputs"))
            .and_then(|i| i.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    let mut out = Vec::new();
    for input in inputs_of(component) {
        if input.starts_with("nano-slot-") {
            for upstream in inputs_of(&input) {
                if upstream != PARKED {
                    out.push(upstream);
                }
            }
        } else {
            out.push(input);
        }
    }
    out
}

#[cfg(test)]
/// `${VAR:-default}` → `0` (a bare one is not TOML; both sides get the same).
pub(crate) fn without_env(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        match rest[start..].find('}') {
            Some(end) => {
                out.push('0');
                rest = &rest[start + end + 1..];
            }
            None => {
                rest = &rest[start..];
                break;
            }
        }
    }
    out.push_str(rest);
    out
}


#[cfg(test)]
#[path = "fanin_slots_tests.rs"]
mod tests;
