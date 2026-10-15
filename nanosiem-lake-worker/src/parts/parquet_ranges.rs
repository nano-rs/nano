// SPDX-License-Identifier: AGPL-3.0-or-later

//! Independently authenticated Parquet reads. Digests are carried in the
//! manifest authenticated by owner-signed provenance. Unverified footer
//! offsets are never trusted.
use anyhow::{bail, ensure, Context, Result};
use parquet::file::reader::{FileReader, SerializedFileReader};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

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
        previous_end = end;
    }
    ensure!(footer, "missing signed Parquet footer");
    Ok(())
}

/// Hash a closed writer file in bounded buffers, including dictionary pages.
/// Page indexes and bloom bitsets are intentionally excluded: consumers must
/// not use them unless separately authenticated.
pub fn build(path: &Path) -> Result<Vec<ParquetRangeDigest>> {
    let reader = SerializedFileReader::new(File::open(path)?)?;
    let metadata = reader.metadata();
    ensure!(
        metadata
            .num_row_groups()
            .checked_mul(metadata.file_metadata().schema_descr().num_columns())
            .is_some_and(|count| count < 65_536),
        "too many Parquet ranges"
    );
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
        for column in row_group.columns() {
            let (offset, bytes) = column.byte_range();
            ranges.push(ParquetRangeDigest {
                offset,
                bytes,
                sha256: String::new(),
                row_group: Some(u32::try_from(group)?),
                column: Some(column.column_path().string()),
            });
        }
    }
    ranges.push(ParquetRangeDigest {
        offset: footer_offset,
        bytes: footer_bytes,
        sha256: String::new(),
        row_group: None,
        column: None,
    });
    ranges.sort_by_key(|range| range.offset);
    let mut buffer = vec![0; 64 * 1024];
    for range in &mut ranges {
        file.seek(SeekFrom::Start(range.offset))?;
        let mut remaining = range.bytes;
        let mut digest = Sha256::new();
        while remaining > 0 {
            let take = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..take])?;
            digest.update(&buffer[..take]);
            remaining -= take as u64;
        }
        range.sha256 = hex::encode(digest.finalize());
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
        };
        let footer = ParquetRangeDigest {
            offset: 14,
            bytes: 8,
            sha256: "b".repeat(64),
            row_group: None,
            column: None,
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
