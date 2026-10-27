// SPDX-License-Identifier: AGPL-3.0-or-later
//! T2 of strict Parquet validation for LandingBytesV1 responses: full row
//! admission of Root-validated chunks (coordinator decision 2026-10-25).
//!
//! Root T1 (`nanosiem_sovereign_contract::landing_footer`) checked footers
//! only and computed each chunk's length, SHA-256, rows and footer-declared
//! decoded bytes. Root never decodes pages. This runs in the jailed lake
//! worker, on Root's staged copies, and before anything decodes:
//!
//! 1. it reads each staged file ONCE (no symlink follow) into memory and
//!    binds that buffer to Root's facts (exact length and SHA-256); every
//!    later step uses that same buffer, never the path again (pR P2-1);
//! 2. it walks every page header ([`nanosiem_core::parquet_page_bounds`]),
//!    so no page can claim more than the chunk ceiling and no page claims
//!    more values than its bytes or the row group can hold (pR P1-1). The
//!    pages must tile each column exactly and sum to the footer totals Root
//!    bounded. Then parquet-rs's own exact-size check makes the declared
//!    bytes the actual decoded bytes;
//! 3. it runs the bronze admission on those verified buffers
//!    ([`crate::bronze::admit_bronze_bytes_received`]): full OCSF decode,
//!    strict per-event validation and identity merge;
//! 4. it reconciles: every file is admitted with Root's rows and SHA-256,
//!    and no row is refused. The worker's converter already prechecked
//!    every row, so a refusal here means the chunk is not what Root
//!    validated.
//!
//! Any failure refuses the whole response with a value-free code. Nothing
//! here publishes; the caller publishes only a returned admission.
use crate::bronze::{admit_bronze_bytes_received, BronzeAdmission, IngestTimes};
use crate::enrichment::BronzeIngestEnricher;
use bytes::Bytes;
use nanosiem_core::parquet_page_bounds::{walk_pages, ColumnSpan};
use parquet::file::metadata::ParquetMetaDataReader;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::PathBuf;

/// Chunks per response (LandingBytesV1 `MAX_CHUNKS`).
pub const MAX_CHUNKS: usize = 500;
/// Encoded bytes per chunk (LandingBytesV1 `MAX_CHUNK_BYTES`).
pub const MAX_CHUNK_BYTES: u64 = 32 * 1024 * 1024;
/// Decoded bytes per chunk. Accepted contract constant (coordinator
/// 2026-10-25), equal to Root T1's `MAX_CHUNK_DECLARED_DECODED`.
pub const MAX_CHUNK_DECODED: u64 = 64 * 1024 * 1024;
/// Decoded bytes per response, equal to Root T1's
/// `MAX_RESPONSE_DECLARED_DECODED`.
pub const MAX_RESPONSE_DECODED: u64 = 1024 * 1024 * 1024;

/// Root-computed T1 facts for one chunk, carried with Root's staged copy.
#[derive(Clone, PartialEq, Eq)]
pub struct RootChunkFacts {
    pub ordinal: u32,
    pub encoded_len: u64,
    pub sha256: [u8; 32],
    pub rows: u64,
    pub declared_decoded: u64,
}

impl std::fmt::Debug for RootChunkFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RootChunkFacts([redacted])")
    }
}

/// One staged chunk: an absolute private `.parquet` path written by Root
/// from the bytes it validated, plus those facts.
#[derive(Debug, Clone)]
pub struct StagedChunk {
    pub path: PathBuf,
    pub facts: RootChunkFacts,
}

/// Value-free refusal codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LandingAdmissionRefusal {
    #[error("staged chunk set is not a validated response")]
    Shape,
    #[error("staged chunk bytes differ from Root's facts")]
    Bytes,
    #[error("staged chunk footer refused")]
    Footer,
    #[error("staged chunk pages refused")]
    Pages,
    #[error("staged chunk decoded size exceeds its ceiling or Root's facts")]
    DecodedCeiling,
    #[error("staged chunk rows differ from Root's facts")]
    Rows,
    #[error("bronze admission refused the staged chunks")]
    Admission,
}

/// Admission of a whole Root-validated response.
pub struct LandingAdmitted {
    pub admission: BronzeAdmission,
    /// Page-proven decoded bytes over all chunks.
    pub decoded: u64,
}

impl std::fmt::Debug for LandingAdmitted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LandingAdmitted")
            .field("files", &self.admission.files.len())
            .field("decoded", &self.decoded)
            .finish_non_exhaustive()
    }
}

/// Bind, bound, admit and reconcile one Root-validated response.
pub fn admit_root_validated_chunks(
    staged: &[StagedChunk],
    tenant_id: &str,
    enricher: &BronzeIngestEnricher,
    times: &IngestTimes,
) -> Result<LandingAdmitted, LandingAdmissionRefusal> {
    if staged.is_empty() || staged.len() > MAX_CHUNKS {
        return Err(LandingAdmissionRefusal::Shape);
    }
    let mut sources = Vec::with_capacity(staged.len());
    let mut unique = BTreeSet::new();
    let (mut rows, mut decoded) = (0u64, 0u64);
    for (index, chunk) in staged.iter().enumerate() {
        if chunk.facts.ordinal as usize != index || !unique.insert(chunk.path.clone()) {
            return Err(LandingAdmissionRefusal::Shape);
        }
        let (chunk_decoded, bytes) = check_chunk(chunk)?;
        decoded = decoded
            .checked_add(chunk_decoded)
            .filter(|total| *total <= MAX_RESPONSE_DECODED)
            .ok_or(LandingAdmissionRefusal::DecodedCeiling)?;
        rows = rows.checked_add(chunk.facts.rows).ok_or(LandingAdmissionRefusal::Rows)?;
        sources.push((chunk.path.clone(), bytes));
    }
    let (admission, refused_rows, _refused_sources) =
        admit_bronze_bytes_received(&sources, tenant_id, enricher, times).map_err(|_| LandingAdmissionRefusal::Admission)?;
    if !refused_rows.is_empty() {
        return Err(LandingAdmissionRefusal::Rows);
    }
    if admission.source_files != staged.len() || admission.files.len() != staged.len() || admission.source_rows != rows {
        return Err(LandingAdmissionRefusal::Rows);
    }
    for chunk in staged {
        let file = admission
            .files
            .iter()
            .find(|file| file.path == chunk.path)
            .ok_or(LandingAdmissionRefusal::Rows)?;
        if file.rows != chunk.facts.rows {
            return Err(LandingAdmissionRefusal::Rows);
        }
        // Admission hashed the same verified buffer it decoded (never the path).
        if file.sha256 != hex::encode(chunk.facts.sha256) || file.bytes != chunk.facts.encoded_len {
            return Err(LandingAdmissionRefusal::Bytes);
        }
    }
    Ok(LandingAdmitted { admission, decoded })
}

/// Steps 1 and 2 for one chunk. Returns its page-proven decoded bytes and
/// the one verified buffer every later step decodes.
fn check_chunk(chunk: &StagedChunk) -> Result<(u64, Bytes), LandingAdmissionRefusal> {
    let facts = &chunk.facts;
    if !chunk.path.is_absolute()
        || chunk.path.extension().and_then(|e| e.to_str()) != Some("parquet")
        || facts.encoded_len == 0
        || facts.encoded_len > MAX_CHUNK_BYTES
        || facts.rows == 0
        || facts.declared_decoded == 0
        || facts.declared_decoded > MAX_CHUNK_DECODED
    {
        return Err(LandingAdmissionRefusal::Shape);
    }
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&chunk.path)
        .map_err(|_| LandingAdmissionRefusal::Bytes)?;
    if !file.metadata().map_err(|_| LandingAdmissionRefusal::Bytes)?.is_file() {
        return Err(LandingAdmissionRefusal::Bytes);
    }
    let mut bytes = Vec::with_capacity(facts.encoded_len as usize);
    file.take(facts.encoded_len + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LandingAdmissionRefusal::Bytes)?;
    if bytes.len() as u64 != facts.encoded_len || <[u8; 32]>::from(Sha256::digest(&bytes)) != facts.sha256 {
        return Err(LandingAdmissionRefusal::Bytes);
    }
    // Root's T1 scanner already accepted this exact footer (same SHA-256).
    let bytes = Bytes::from(bytes);
    let metadata = ParquetMetaDataReader::new()
        .parse_and_finish(&bytes)
        .map_err(|_| LandingAdmissionRefusal::Footer)?;
    if u64::try_from(metadata.file_metadata().num_rows()).ok() != Some(facts.rows) {
        return Err(LandingAdmissionRefusal::Rows);
    }
    let mut columns = Vec::new();
    for group in metadata.row_groups() {
        let rows = u64::try_from(group.num_rows()).map_err(|_| LandingAdmissionRefusal::Footer)?;
        for column in group.columns() {
            let (start, _) = column.byte_range();
            columns.push(ColumnSpan {
                start,
                compressed: u64::try_from(column.compressed_size()).map_err(|_| LandingAdmissionRefusal::Footer)?,
                uncompressed: u64::try_from(column.uncompressed_size()).map_err(|_| LandingAdmissionRefusal::Footer)?,
                num_values: u64::try_from(column.num_values()).map_err(|_| LandingAdmissionRefusal::Footer)?,
                rows,
                value_width: plain_value_width(column.column_type(), column.column_descr().type_length()),
            });
        }
    }
    let totals = walk_pages(&bytes, &columns, MAX_CHUNK_DECODED, MAX_CHUNK_DECODED)
        .map_err(|_| LandingAdmissionRefusal::Pages)?;
    if totals.decoded != facts.declared_decoded {
        return Err(LandingAdmissionRefusal::DecodedCeiling);
    }
    Ok((totals.decoded, bytes))
}

/// Smallest PLAIN encoding of one dictionary value of `physical` (BYTE_ARRAY:
/// its 4-byte length prefix). Bounds a dictionary page's value count by its
/// own bytes.
fn plain_value_width(physical: parquet::basic::Type, type_length: i32) -> u64 {
    use parquet::basic::Type;
    match physical {
        Type::BOOLEAN => 1,
        Type::INT32 | Type::FLOAT | Type::BYTE_ARRAY => 4,
        Type::INT64 | Type::DOUBLE => 8,
        Type::INT96 => 12,
        Type::FIXED_LEN_BYTE_ARRAY => u64::try_from(type_length).unwrap_or(1).max(1),
    }
}

#[cfg(test)]
#[path = "landing_admission_tests.rs"]
mod tests;
