// SPDX-License-Identifier: AGPL-3.0-or-later

//! Independently authenticated Parquet reads. Digests are carried in the
//! manifest authenticated by owner-signed provenance. Unverified footer
//! offsets are never trusted.
use anyhow::{bail, ensure, Context, Result};
use parquet::file::metadata::{PageIndexPolicy, ParquetMetaDataReader};
use parquet::file::reader::{FileReader, SerializedFileReader};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// The existing wire envelope cannot represent this part; its data remains
/// readable through the verified whole-file path.
#[derive(Debug, thiserror::Error)]
#[error("Parquet range manifest exceeds its wire envelope")]
pub struct ManifestCapacity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParquetRangeDigest {
    pub offset: u64,
    pub bytes: u64,
    pub sha256: String,
    /// Both absent for the footer (including its length and final PAR1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_group: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<String>,
    /// Signed offset-index locations and page hashes. Empty on legacy manifests.
    /// A dictionary, when present, is the first entry and has no first_row.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pages: Vec<ParquetPageDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParquetPageDigest {
    pub offset: u64,
    pub bytes: u64,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<u64>,
}

pub fn validate(ranges: &[ParquetRangeDigest], file_bytes: u64, groups: u32) -> Result<()> {
    ensure!(
        !ranges.is_empty() && ranges.len() <= 65_536,
        "invalid Parquet range count"
    );
    let mut previous_end = 4;
    let mut seen = BTreeSet::new();
    let mut footer = false;
    for range in ranges {
        let end = range
            .offset
            .checked_add(range.bytes)
            .context("Parquet range overflow")?;
        ensure!(
            range.bytes > 0 && range.offset >= previous_end && end <= file_bytes,
            "Parquet ranges overlap or exceed the file"
        );
        ensure!(
            super::is_sha256_hex(&range.sha256),
            "invalid Parquet range digest"
        );
        match (&range.row_group, &range.column) {
            (Some(group), Some(column)) => {
                ensure!(
                    !footer && *group < groups && !column.is_empty() && column.len() <= 1024,
                    "invalid Parquet column range"
                );
                ensure!(
                    seen.insert((*group, column)),
                    "duplicate Parquet column range"
                );
            }
            (None, None) => {
                ensure!(
                    !footer && end == file_bytes && range.bytes >= 8,
                    "invalid Parquet footer range"
                );
                footer = true;
            }
            _ => bail!("incomplete Parquet range identity"),
        }
        if !range.pages.is_empty() {
            ensure!(range.column.is_some(), "footer cannot carry pages");
            let mut next = range.offset;
            let mut first_row = None;
            for (at, page) in range.pages.iter().enumerate() {
                ensure!(
                    page.offset == next && page.bytes > 0 && super::is_sha256_hex(&page.sha256),
                    "invalid signed Parquet page range"
                );
                next = page
                    .offset
                    .checked_add(page.bytes)
                    .context("page range overflow")?;
                ensure!(next <= end, "page exceeds column chunk");
                match page.first_row {
                    None => ensure!(at == 0, "dictionary must precede data pages"),
                    Some(row) => {
                        ensure!(
                            first_row.map_or(row == 0, |previous| row >= previous),
                            "invalid page row order"
                        );
                        first_row = Some(row);
                    }
                }
            }
            ensure!(
                next == end && first_row.is_some(),
                "incomplete signed page coverage"
            );
        }
        previous_end = end;
    }
    ensure!(footer, "missing signed Parquet footer");
    Ok(())
}

/// Hash a closed writer file in bounded buffers, including dictionary pages.
/// The offset index is copied into the signed manifest. Page hashes are
/// computed in the same streaming pass as each column hash; no extra file read.
/// Encoded page indexes and bloom bitsets remain outside the signed ranges.
pub fn build(path: &Path) -> Result<Vec<ParquetRangeDigest>> {
    let reader = SerializedFileReader::new(File::open(path)?)?;
    let mut metadata = reader.metadata().clone();
    // Decode offset indexes only, and only when their expanded page hashes
    // fit a small share of this role's memory and the existing wire envelope.
    let page_budget = crate::cgroup_memory::for_process()
        .limit()
        .map_or(MAX_MANIFEST_BYTES, |limit| {
            (limit.bytes / 64).min(MAX_MANIFEST_BYTES)
        });
    let offset_bytes = metadata
        .row_groups()
        .iter()
        .flat_map(|group| group.columns())
        .try_fold(0_u64, |sum, column| {
            sum.checked_add(column.offset_index_length().unwrap_or(0).max(0) as u64)
        });
    if offset_bytes.is_some_and(|bytes| bytes <= page_budget / 8) {
        let mut pages = ParquetMetaDataReader::new_with_metadata(metadata)
            .with_offset_index_policy(PageIndexPolicy::Optional);
        pages.read_page_indexes(&File::open(path)?)?;
        metadata = pages.finish()?;
    }
    if !metadata
        .num_row_groups()
        .checked_mul(metadata.file_metadata().schema_descr().num_columns())
        .is_some_and(|count| count < 65_536)
    {
        return Err(ManifestCapacity.into());
    }
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    ensure!(size >= 12, "truncated Parquet file");
    file.seek(SeekFrom::End(-8))?;
    let mut trailer = [0_u8; 8];
    file.read_exact(&mut trailer)?;
    ensure!(&trailer[4..] == b"PAR1", "invalid Parquet trailer");
    let footer_bytes = u64::from(u32::from_le_bytes(trailer[..4].try_into()?)) + 8;
    let footer_offset = size
        .checked_sub(footer_bytes)
        .context("invalid Parquet footer length")?;
    let mut ranges = Vec::new();
    for (group, row_group) in metadata.row_groups().iter().enumerate() {
        for (column_index, column) in row_group.columns().iter().enumerate() {
            let (offset, bytes) = column.byte_range();
            ranges.push(ParquetRangeDigest {
                offset,
                bytes,
                sha256: String::new(),
                row_group: Some(u32::try_from(group)?),
                column: Some(column.column_path().string()),
                pages: metadata
                    .offset_index()
                    .and_then(|indexes| indexes.get(group)?.get(column_index))
                    .map(|index| {
                        let mut pages = Vec::new();
                        if let Some(first) = index.page_locations().first() {
                            let first_offset = u64::try_from(first.offset).unwrap_or(0);
                            if first_offset > offset {
                                pages.push(ParquetPageDigest {
                                    offset,
                                    bytes: first_offset - offset,
                                    sha256: String::new(),
                                    first_row: None,
                                });
                            }
                        }
                        for page in index.page_locations() {
                            pages.push(ParquetPageDigest {
                                offset: page.offset as u64,
                                bytes: page.compressed_page_size as u64,
                                sha256: String::new(),
                                first_row: Some(page.first_row_index as u64),
                            });
                        }
                        pages
                    })
                    .unwrap_or_default(),
            });
        }
    }
    ranges.push(ParquetRangeDigest {
        offset: footer_offset,
        bytes: footer_bytes,
        sha256: String::new(),
        row_group: None,
        column: None,
        pages: Vec::new(),
    });
    ranges.sort_by_key(|range| range.offset);
    let mut buffer = vec![0; 64 * 1024];
    for range in &mut ranges {
        // Offset indexes describe data pages only. If a writer used another
        // page kind or left a gap, keep the legacy chunk instead of hashing
        // beyond the page vector or emitting incomplete page authority.
        if !range.pages.is_empty() {
            let end = range
                .offset
                .checked_add(range.bytes)
                .context("column range overflow")?;
            let covered = range.pages.iter().try_fold(range.offset, |next, page| {
                (page.offset == next && page.bytes > 0)
                    .then(|| next.checked_add(page.bytes))
                    .flatten()
            });
            if covered != Some(end) {
                range.pages.clear();
            }
        }
        file.seek(SeekFrom::Start(range.offset))?;
        let mut remaining = range.bytes;
        let mut digest = Sha256::new();
        let mut page_digest = Sha256::new();
        let mut page_index = 0;
        let mut page_remaining = range.pages.first().map_or(remaining, |page| page.bytes);
        while remaining > 0 {
            let take = remaining.min(page_remaining).min(buffer.len() as u64) as usize;
            ensure!(take > 0, "empty Parquet page");
            file.read_exact(&mut buffer[..take])?;
            digest.update(&buffer[..take]);
            if !range.pages.is_empty() {
                page_digest.update(&buffer[..take]);
            }
            remaining -= take as u64;
            page_remaining -= take as u64;
            if page_remaining == 0 && !range.pages.is_empty() {
                range.pages[page_index].sha256 = hex::encode(page_digest.finalize_reset());
                page_index += 1;
                page_remaining = range
                    .pages
                    .get(page_index)
                    .map_or(remaining, |page| page.bytes);
            }
        }
        range.sha256 = hex::encode(digest.finalize());
    }
    // Preserve the existing wire envelope. Very wide parts keep legacy chunk
    // manifests instead of failing a flush because page metadata grew too large.
    if serde_json::to_vec(&ranges)?.len() as u64 > page_budget {
        for range in &mut ranges {
            range.pages.clear();
        }
    }
    if serde_json::to_vec(&ranges)?.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(ManifestCapacity.into());
    }
    validate(&ranges, size, u32::try_from(metadata.num_row_groups())?)?;
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_unbounded_overlapping_and_ambiguous_ranges() {
        let column = ParquetRangeDigest {
            offset: 4,
            bytes: 10,
            sha256: "a".repeat(64),
            row_group: Some(0),
            column: Some("ext".into()),
            pages: Vec::new(),
        };
        let footer = ParquetRangeDigest {
            offset: 14,
            bytes: 8,
            sha256: "b".repeat(64),
            row_group: None,
            column: None,
            pages: Vec::new(),
        };
        validate(&[column.clone(), footer.clone()], 22, 1).unwrap();
        for bad in [
            ParquetRangeDigest {
                offset: u64::MAX,
                ..column.clone()
            },
            ParquetRangeDigest {
                offset: 3,
                ..column.clone()
            },
            ParquetRangeDigest {
                row_group: Some(1),
                ..column.clone()
            },
            ParquetRangeDigest {
                column: None,
                ..column.clone()
            },
            ParquetRangeDigest {
                sha256: "A".repeat(64),
                ..column.clone()
            },
        ] {
            assert!(validate(&[bad, footer.clone()], 22, 1).is_err());
        }
        assert!(validate(&[column], 22, 1).is_err());
        assert!(validate(&[footer], 23, 1).is_err());
    }
}
