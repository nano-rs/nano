// SPDX-License-Identifier: AGPL-3.0-or-later

//! The byte-bounded bronze sink buffer in a tenant parser base (NAN-3523).
//!
//! Bases recorded before NAN-3523 bound the `ocsf_parquet_bronze` memory
//! buffer by EVENTS (`max_events = ${VECTOR_LAKE_BUFFER_MAX_EVENTS:-20000}`);
//! an event may be up to 4 MiB, so that buffer could hold ~80 GiB.
//! [`upgrade_bronze_buffer_bytes`] derives a base whose buffer is bounded by
//! in-memory BYTES instead ([`BRONZE_BUFFER_BYTES`], the section the
//! canonical `config/vector` sink and the `deploy.rs` generator carry): still
//! `type = "memory"` (a disk buffer would ACK the source before the R2 PUT)
//! and `when_full = "block"`. The edit is confined to that one section of the
//! two `_ocsf_sink.toml` copies; nothing else in the base changes, so the HEC
//! config, the output guard and the batch policy keep their bytes.

use super::archive::BundleTree;
use super::bronze_row_contract::BRONZE_SINK_FILES;
use super::overlay::LAKE_SINK_FILE;
use super::TenantBundleError;

/// The bronze sink buffer's table header.
pub const BRONZE_BUFFER_HEADER: &str = "[sinks.ocsf_parquet_bronze.buffer]\n";

/// The event-bounded buffer section every base before NAN-3523 carries.
pub const LEGACY_BRONZE_BUFFER: &str = "[sinks.ocsf_parquet_bronze.buffer]\n\
type = \"memory\"\n\
max_events = ${VECTOR_LAKE_BUFFER_MAX_EVENTS:-20000}\n\
when_full = \"block\"\n";

/// The byte-bounded buffer section (NAN-3523), byte-identical to the one in
/// `config/vector/{sources/parsers,backup}/_ocsf_sink.toml` and the
/// `deploy.rs` lake sink generator (pinned by tests).
pub const BRONZE_BUFFER_BYTES: &str = "[sinks.ocsf_parquet_bronze.buffer]\n\
# NAN-3523: bounded by in-memory BYTES, not events: an event may be up to\n\
# 4 MiB, so 20000 events could hold ~80 GiB. 64 MiB is four of the hosted\n\
# Worker's 16 MiB batches, a small slice of the smallest Container. Memory\n\
# (never disk) keeps the source ACK behind the completed PUT; when full it\n\
# blocks, pushing back on the source and the durable raw handoff upstream.\n\
type = \"memory\"\n\
max_size = ${VECTOR_LAKE_BUFFER_MAX_BYTES:-67108864}\n\
when_full = \"block\"\n";

fn base_error(what: &str) -> TenantBundleError {
    TenantBundleError::Base(format!("bronze buffer bytes: {what}"))
}

/// Whether the base's lake sink buffer is already byte-bounded.
pub fn has_bronze_buffer_bytes(base: &BundleTree) -> bool {
    base.text(LAKE_SINK_FILE)
        .is_ok_and(|text| text.contains(BRONZE_BUFFER_BYTES))
}

/// Derive the base whose bronze sink buffer is bounded by bytes: replace the
/// legacy event-bounded buffer section with [`BRONZE_BUFFER_BYTES`] in every
/// `_ocsf_sink.toml` copy, and change nothing else. Refuses a base that
/// already carries it, or whose buffer section is not exactly the legacy one
/// (a hand-edited buffer is never silently overwritten).
pub fn upgrade_bronze_buffer_bytes(base: &BundleTree) -> Result<BundleTree, TenantBundleError> {
    if has_bronze_buffer_bytes(base) {
        return Err(base_error(
            "the base already carries the byte-bounded buffer",
        ));
    }
    let mut tree = base.clone();
    for path in BRONZE_SINK_FILES {
        let Ok(text) = base.text(path) else {
            if path == LAKE_SINK_FILE {
                return Err(base_error("the base has no lake sink"));
            }
            continue;
        };
        if text.matches(BRONZE_BUFFER_HEADER).count() != 1
            || text.matches(LEGACY_BRONZE_BUFFER).count() != 1
        {
            return Err(base_error(&format!(
                "{path} does not carry exactly one legacy event-bounded buffer section"
            )));
        }
        let edited = text.replacen(LEGACY_BRONZE_BUFFER, BRONZE_BUFFER_BYTES, 1);
        tree.put(path, edited.into_bytes());
    }
    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANONICAL_SINK: &str =
        include_str!("../../../../config/vector/sources/parsers/_ocsf_sink.toml");
    const CANONICAL_BACKUP_SINK: &str =
        include_str!("../../../../config/vector/backup/_ocsf_sink.toml");

    fn buffer_section(text: &str) -> String {
        let start = text.find(BRONZE_BUFFER_HEADER).expect("buffer header");
        let rest = &text[start..];
        let end = rest[BRONZE_BUFFER_HEADER.len()..]
            .find("\n[")
            .map_or(rest.len(), |i| BRONZE_BUFFER_HEADER.len() + i + 1);
        rest[..end].trim_end_matches('\n').to_string()
    }

    fn base_with(sink: &str, backup: Option<&str>) -> BundleTree {
        let mut tree = BundleTree::default();
        tree.put(LAKE_SINK_FILE, sink.as_bytes().to_vec());
        if let Some(backup) = backup {
            tree.put("backup/_ocsf_sink.toml", backup.as_bytes().to_vec());
        }
        tree.put("02-hec-source.toml", b"untouched\n".to_vec());
        tree
    }

    fn legacy_sink() -> String {
        CANONICAL_SINK.replace(BRONZE_BUFFER_BYTES, LEGACY_BRONZE_BUFFER)
    }

    #[test]
    fn the_section_is_the_canonical_sinks_own() {
        assert_eq!(
            buffer_section(CANONICAL_SINK),
            BRONZE_BUFFER_BYTES.trim_end()
        );
        assert_eq!(
            buffer_section(CANONICAL_BACKUP_SINK),
            BRONZE_BUFFER_BYTES.trim_end()
        );
        let parsed: toml::Table = BRONZE_BUFFER_BYTES
            .replace("${VECTOR_LAKE_BUFFER_MAX_BYTES:-67108864}", "67108864")
            .parse()
            .unwrap();
        let buffer = &parsed["sinks"]["ocsf_parquet_bronze"]["buffer"];
        assert_eq!(buffer["type"].as_str(), Some("memory"));
        assert_eq!(buffer["max_size"].as_integer(), Some(64 * 1024 * 1024));
        assert_eq!(buffer["when_full"].as_str(), Some("block"));
        assert!(
            buffer.get("max_events").is_none(),
            "max_size and max_events are exclusive"
        );
    }

    #[test]
    fn upgrade_changes_only_the_buffer_section_of_both_sink_copies() {
        let legacy = legacy_sink();
        let legacy_backup =
            CANONICAL_BACKUP_SINK.replace(BRONZE_BUFFER_BYTES, LEGACY_BRONZE_BUFFER);
        assert!(
            legacy.contains(LEGACY_BRONZE_BUFFER) && legacy_backup.contains(LEGACY_BRONZE_BUFFER)
        );
        let base = base_with(&legacy, Some(&legacy_backup));
        assert!(!has_bronze_buffer_bytes(&base));
        let next = upgrade_bronze_buffer_bytes(&base).unwrap();
        assert!(has_bronze_buffer_bytes(&next));
        assert_eq!(next.text(LAKE_SINK_FILE).unwrap(), CANONICAL_SINK);
        assert_eq!(
            next.text("backup/_ocsf_sink.toml").unwrap(),
            CANONICAL_BACKUP_SINK
        );
        assert_eq!(
            next.files["02-hec-source.toml"],
            base.files["02-hec-source.toml"]
        );
        assert_eq!(next.files.len(), base.files.len());
    }

    #[test]
    fn upgrade_tolerates_a_base_without_the_backup_copy() {
        let next = upgrade_bronze_buffer_bytes(&base_with(&legacy_sink(), None)).unwrap();
        assert_eq!(next.text(LAKE_SINK_FILE).unwrap(), CANONICAL_SINK);
        assert!(next.file("backup/_ocsf_sink.toml").is_none());
    }

    #[test]
    fn upgrade_refuses_an_upgraded_edited_or_missing_buffer() {
        let already = upgrade_bronze_buffer_bytes(&base_with(CANONICAL_SINK, None)).unwrap_err();
        assert!(already.to_string().contains("already carries"), "{already}");
        let edited = legacy_sink().replace(
            "VECTOR_LAKE_BUFFER_MAX_EVENTS:-20000",
            "VECTOR_LAKE_BUFFER_MAX_EVENTS:-5000",
        );
        let refused = upgrade_bronze_buffer_bytes(&base_with(&edited, None)).unwrap_err();
        assert!(
            refused.to_string().contains("legacy event-bounded buffer"),
            "{refused}"
        );
        let no_sink = upgrade_bronze_buffer_bytes(&BundleTree::default()).unwrap_err();
        assert!(no_sink.to_string().contains("no lake sink"), "{no_sink}");
    }
}
