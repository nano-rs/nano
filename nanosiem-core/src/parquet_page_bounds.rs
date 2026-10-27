// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded walk of every page header in a Parquet file's column chunks.
//!
//! parquet-rs 58.4 allocates `uncompressed_page_size` from each page header
//! before it decompresses the page (`serialized_reader.rs` `decode_page`),
//! then requires the decompressed length to equal it exactly. Page headers
//! are therefore the real decoded-size claims, and footer totals alone do
//! not bound them. This walk reads only page headers (never page data) and
//! ties the pages to the footer: per column chunk, the headers plus
//! compressed pages must tile the chunk's byte range exactly, and their
//! header-plus-uncompressed sizes must sum to the footer's
//! `total_uncompressed_size`. That is how the parquet-rs writer computes both
//! totals. Work is linear in the page count.
//!
//! It also binds the value counts decoders size allocations from (H02 CP34,
//! pR P1-1): parquet-rs sizes a dictionary from
//! `DictionaryPageHeader.num_values` (`DictDecoder::set_dict` resizes to it;
//! the byte-array reader reserves that many offsets), not from the page bytes.
//! A dictionary page may claim at most `uncompressed_page_size / value_width`
//! values; a data page (v1 or v2) at most the row group's rows, with nulls
//! and v2 rows bounded the same way; and a column's data-page values must sum
//! to the footer's `num_values`.
//!
//! What it does NOT cover: claims it does not parse. The view-array and
//! byte-stream-split decoders also size from counts
//! (`byte_view_array.rs`, `byte_stream_split_decoder.rs`); they are
//! unreachable while Root T1 pins the bronze schema to plain/dictionary
//! encodings of flat INT64/BYTE_ARRAY columns.

/// One column chunk as its footer declares it: the byte range start
/// (dictionary page offset, else data page offset) and the footer's
/// `total_compressed_size` / `total_uncompressed_size`. Callers copy these
/// from their own decoded footer, so this module needs no Parquet decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColumnSpan {
    pub start: u64,
    pub compressed: u64,
    pub uncompressed: u64,
    /// The footer's `ColumnMetaData.num_values`.
    pub num_values: u64,
    /// The row group's `num_rows` (the bronze schema is flat: one value per row).
    pub rows: u64,
    /// The smallest encoded size of one PLAIN dictionary value of this
    /// column's physical type (INT64 8, INT32 4, BYTE_ARRAY 4 for its length
    /// prefix); at least 1.
    pub value_width: u64,
}

/// One page header is a few hundred bytes (statistics are truncated).
pub const MAX_PAGE_HEADER_BYTES: usize = 64 * 1024;
/// Pages per column chunk.
pub const MAX_PAGES_PER_COLUMN: usize = 4096;
const MAX_HEADER_NESTING: usize = 8;
const MAX_HEADER_LIST: usize = 1024;

const DATA_PAGE: i64 = 0;
const DICTIONARY_PAGE: i64 = 2;
const DATA_PAGE_V2: i64 = 3;

/// Value-free refusal codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PageBoundsRefusal {
    #[error("column chunk byte range is outside the file")]
    Layout,
    #[error("Parquet page header refused")]
    Header,
    #[error("Parquet pages do not match the footer totals")]
    Totals,
    #[error("Parquet page decoded size exceeds its ceiling")]
    Ceiling,
}

/// Totals proven from the page headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageTotals {
    pub pages: u64,
    /// Sum of header + uncompressed page bytes over every column chunk
    /// (equal, column by column, to the footer's uncompressed totals).
    pub decoded: u64,
    /// Largest single uncompressed page (the largest one decoder allocation).
    pub largest_page: u64,
}

/// Walk every column chunk in `file`. A page may claim at most
/// `max_page_decoded` uncompressed bytes, and the whole file at most
/// `max_file_decoded`.
pub fn walk_pages(
    file: &[u8],
    columns: &[ColumnSpan],
    max_page_decoded: u64,
    max_file_decoded: u64,
) -> Result<PageTotals, PageBoundsRefusal> {
    let mut totals = PageTotals {
        pages: 0,
        decoded: 0,
        largest_page: 0,
    };
    for column in columns {
        let start = usize::try_from(column.start).map_err(|_| PageBoundsRefusal::Layout)?;
        let length = usize::try_from(column.compressed).map_err(|_| PageBoundsRefusal::Layout)?;
        let end = start.checked_add(length).ok_or(PageBoundsRefusal::Layout)?;
        if length == 0 || end > file.len() {
            return Err(PageBoundsRefusal::Layout);
        }
        let declared_compressed = column.compressed;
        let declared_uncompressed = column.uncompressed;
        let width = column.value_width.max(1);
        let (mut at, mut compressed, mut uncompressed, mut pages) = (start, 0u64, 0u64, 0usize);
        let mut values = 0u64;
        while at < end {
            let window = &file[at..end.min(at + MAX_PAGE_HEADER_BYTES)];
            let header = read_page_header(window)?;
            let is_dictionary = header.page_type == DICTIONARY_PAGE;
            if is_dictionary && pages != 0 {
                return Err(PageBoundsRefusal::Header);
            }
            if header.uncompressed > max_page_decoded {
                return Err(PageBoundsRefusal::Ceiling);
            }
            match header.counts {
                Counts::Dictionary { values: n } if n > header.uncompressed / width => {
                    return Err(PageBoundsRefusal::Ceiling);
                }
                Counts::Dictionary { .. } => {}
                Counts::Data { values: n, nulls, rows } => {
                    if n > column.rows || nulls > n || rows.is_some_and(|r| r > column.rows) {
                        return Err(PageBoundsRefusal::Ceiling);
                    }
                    values = values.checked_add(n).ok_or(PageBoundsRefusal::Totals)?;
                }
            }
            let header_len = header.length as u64;
            let page_end = at
                .checked_add(header.length)
                .and_then(|v| v.checked_add(usize::try_from(header.compressed).ok()?))
                .ok_or(PageBoundsRefusal::Header)?;
            if page_end > end {
                return Err(PageBoundsRefusal::Header);
            }
            compressed = compressed
                .checked_add(header_len + header.compressed)
                .ok_or(PageBoundsRefusal::Totals)?;
            uncompressed = uncompressed
                .checked_add(header_len + header.uncompressed)
                .ok_or(PageBoundsRefusal::Totals)?;
            totals.largest_page = totals.largest_page.max(header.uncompressed);
            pages += 1;
            if pages > MAX_PAGES_PER_COLUMN {
                return Err(PageBoundsRefusal::Header);
            }
            at = page_end;
        }
        if at != end
            || compressed != declared_compressed
            || uncompressed != declared_uncompressed
            || values != column.num_values
        {
            return Err(PageBoundsRefusal::Totals);
        }
        totals.pages += pages as u64;
        totals.decoded = totals
            .decoded
            .checked_add(uncompressed)
            .ok_or(PageBoundsRefusal::Ceiling)?;
        if totals.decoded > max_file_decoded {
            return Err(PageBoundsRefusal::Ceiling);
        }
    }
    Ok(totals)
}

struct PageHeader {
    length: usize,
    page_type: i64,
    uncompressed: u64,
    compressed: u64,
    counts: Counts,
}

/// The value counts of the one type-specific header a page must carry.
#[derive(Clone, Copy)]
enum Counts {
    /// 7: DictionaryPageHeader {1: num_values}.
    Dictionary { values: u64 },
    /// 5: DataPageHeader {1: num_values}, or 8: DataPageHeaderV2
    /// {1: num_values, 2: num_nulls, 3: num_rows}.
    Data { values: u64, nulls: u64, rows: Option<u64> },
}

/// Thrift compact `PageHeader`: 1 type, 2 uncompressed_page_size,
/// 3 compressed_page_size (required i32s) and the one type-specific header
/// (5 data, 7 dictionary, 8 data v2) with its counts; every other field is
/// skipped structurally under nesting, list and byte bounds.
fn read_page_header(bytes: &[u8]) -> Result<PageHeader, PageBoundsRefusal> {
    let mut r = Reader { bytes, at: 0 };
    let (mut page_type, mut uncompressed, mut compressed) = (None, None, None);
    let mut typed: Option<(i16, [Option<u64>; 3])> = None;
    let mut last = 0i16;
    loop {
        let header = r.byte()?;
        if header == 0 {
            break;
        }
        let kind = header & 0x0f;
        let id = r.field_id(header, last)?;
        last = id;
        match id {
            1..=3 => {
                let value = r.non_negative_i32(kind)?;
                match id {
                    1 => page_type = Some(value),
                    2 => uncompressed = Some(value),
                    _ => compressed = Some(value),
                }
            }
            5 | 7 | 8 => {
                // At most one type-specific header (ids increase strictly).
                if kind != 12 || typed.is_some() {
                    return Err(PageBoundsRefusal::Header);
                }
                typed = Some((id, r.counts_struct(if id == 8 { 3 } else { 1 })?));
            }
            _ => r.skip(kind, 1)?,
        }
    }
    let (Some(page_type), Some(uncompressed), Some(compressed)) = (page_type, uncompressed, compressed) else {
        return Err(PageBoundsRefusal::Header);
    };
    let page_type = page_type as i64;
    let counts = match (page_type, typed) {
        (DATA_PAGE, Some((5, [Some(values), _, _]))) => Counts::Data { values, nulls: 0, rows: None },
        (DICTIONARY_PAGE, Some((7, [Some(values), _, _]))) => Counts::Dictionary { values },
        (DATA_PAGE_V2, Some((8, [Some(values), Some(nulls), Some(rows)]))) => Counts::Data {
            values,
            nulls,
            rows: Some(rows),
        },
        // Index pages, unknown types, a missing or mismatched typed header.
        _ => return Err(PageBoundsRefusal::Header),
    };
    Ok(PageHeader {
        length: r.at,
        page_type,
        uncompressed,
        compressed,
        counts,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, PageBoundsRefusal> {
        let byte = *self.bytes.get(self.at).ok_or(PageBoundsRefusal::Header)?;
        self.at += 1;
        Ok(byte)
    }

    fn advance(&mut self, n: usize) -> Result<(), PageBoundsRefusal> {
        if n > self.bytes.len() - self.at {
            return Err(PageBoundsRefusal::Header);
        }
        self.at += n;
        Ok(())
    }

    fn varint(&mut self) -> Result<u64, PageBoundsRefusal> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = self.byte()?;
            if shift == 63 && byte > 1 {
                return Err(PageBoundsRefusal::Header);
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(PageBoundsRefusal::Header)
    }

    /// A required non-negative i32 (compact type 5).
    fn non_negative_i32(&mut self, kind: u8) -> Result<u64, PageBoundsRefusal> {
        if kind != 5 {
            return Err(PageBoundsRefusal::Header);
        }
        let value = self.zigzag()?;
        if !(0..=i64::from(i32::MAX)).contains(&value) {
            return Err(PageBoundsRefusal::Header);
        }
        Ok(value as u64)
    }

    /// A typed page header struct: its first `wanted` fields as non-negative
    /// i32s when present (num_values; v2 also num_nulls, num_rows), the rest
    /// (encodings, is_sorted, statistics) skipped structurally.
    fn counts_struct(&mut self, wanted: i16) -> Result<[Option<u64>; 3], PageBoundsRefusal> {
        let mut counts = [None; 3];
        let mut last = 0i16;
        loop {
            let header = self.byte()?;
            if header == 0 {
                return Ok(counts);
            }
            let kind = header & 0x0f;
            last = self.field_id(header, last)?;
            match last {
                id if (1..=wanted).contains(&id) => counts[id as usize - 1] = Some(self.non_negative_i32(kind)?),
                _ => self.skip(kind, 2)?,
            }
        }
    }

    fn zigzag(&mut self) -> Result<i64, PageBoundsRefusal> {
        let raw = self.varint()?;
        Ok(((raw >> 1) as i64) ^ -((raw & 1) as i64))
    }

    /// Strictly increasing field ids, so duplicate fields cannot disagree.
    fn field_id(&mut self, header: u8, last: i16) -> Result<i16, PageBoundsRefusal> {
        let delta = (header >> 4) as i16;
        let id = if delta == 0 {
            i16::try_from(self.zigzag()?).map_err(|_| PageBoundsRefusal::Header)?
        } else {
            last.checked_add(delta).ok_or(PageBoundsRefusal::Header)?
        };
        if id <= last {
            return Err(PageBoundsRefusal::Header);
        }
        Ok(id)
    }

    fn skip(&mut self, kind: u8, depth: usize) -> Result<(), PageBoundsRefusal> {
        if depth > MAX_HEADER_NESTING {
            return Err(PageBoundsRefusal::Header);
        }
        match kind {
            1 | 2 => Ok(()),
            3 => self.advance(1),
            4..=6 => self.varint().map(|_| ()),
            7 => self.advance(8),
            8 => {
                let length = usize::try_from(self.varint()?).map_err(|_| PageBoundsRefusal::Header)?;
                self.advance(length)
            }
            9 | 10 => {
                let header = self.byte()?;
                let element = header & 0x0f;
                let short = (header >> 4) as usize;
                let size = if short == 15 {
                    usize::try_from(self.varint()?).map_err(|_| PageBoundsRefusal::Header)?
                } else {
                    short
                };
                if size > MAX_HEADER_LIST || size > self.bytes.len() - self.at {
                    return Err(PageBoundsRefusal::Header);
                }
                for _ in 0..size {
                    match element {
                        1 | 2 => self.advance(1)?,
                        _ => self.skip(element, depth + 1)?,
                    }
                }
                Ok(())
            }
            12 => {
                let mut last = 0i16;
                loop {
                    let header = self.byte()?;
                    if header == 0 {
                        return Ok(());
                    }
                    last = self.field_id(header, last)?;
                    self.skip(header & 0x0f, depth + 1)?;
                }
            }
            _ => Err(PageBoundsRefusal::Header),
        }
    }
}

// Tested against the real bronze encoder in nanosiem-lake-worker
// (landing_admission tests) and the Root T1 tests.
