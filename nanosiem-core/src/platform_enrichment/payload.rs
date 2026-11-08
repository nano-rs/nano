// SPDX-License-Identifier: AGPL-3.0-or-later
//! Section reader for the NANPFB01 payload of a VERIFIED portable container
//! (NAN-4948).
//!
//! Layout (written by `nanpfb::write`, checked by `portable::verify_reader`):
//!
//! ```text
//! "NANPFB01" | u64 LE header length H | header JSON (H bytes)
//! | IPinfo Lite MMDB (mmdb_len bytes, present iff ipinfo_lite is carried)
//! | IOC section (ioc_len bytes): "<value>\t<IocSnapshotInput JSON>\n" per row
//! ```
//!
//! The portable verifier already proved the payload digest, length and that
//! the header states exactly the signed feed set, revisions and expiries, and
//! carries no premium prefix section. This reader only slices it. Every read
//! is still bounded, and an IOC row that does not parse, or names a feed the
//! descriptor does not carry, fails the load instead of being skipped: a
//! verified bundle that does not parse is a publisher bug, and loading half of
//! it would silently drop indicators.

use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    os::unix::fs::{FileExt, OpenOptionsExt},
    path::Path,
    sync::Arc,
};

use anyhow::{bail, ensure, Context, Result};

use super::nanpfb::{Header, IocSnapshotInput, MAGIC};
use super::portable::{self, KeyRing, VerifiedBundle};

/// Same bound `nanpfb::write` applies to one IOC row.
const MAX_IOC_ROW_BYTES: usize = 16_384 + 4096 + 2;
/// Same bound the portable verifier applies to the NANPFB01 header.
const MAX_HEADER_BYTES: u64 = 16_384;

/// Positional reader over `[pos, end)` of a shared open file. Reads never move
/// a shared cursor and never reopen the path, so every byte the loader uses
/// comes from the same inode the verifier hashed (NAN-4948 review P1).
pub struct PosReader {
    file: Arc<File>,
    pos: u64,
    end: u64,
}

impl PosReader {
    pub fn new(file: Arc<File>, pos: u64, end: u64) -> Self {
        Self { file, pos, end }
    }
}

impl Read for PosReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.end.saturating_sub(self.pos);
        if left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(left) as usize;
        let n = self.file.read_at(&mut buf[..want], self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// Open `path` (regular file, never a symlink) ONCE and verify it through that
/// descriptor. The returned handle is the only way the loader reads the
/// payload afterwards; replacing or rewriting the path after this call has no
/// effect on what is loaded.
pub fn open_verified(path: &Path, ring: &KeyRing) -> Result<(Arc<File>, VerifiedBundle), portable::BundleError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(portable::BundleError::Invalid("not a regular file"));
    }
    let len = meta.len();
    if len > portable::MAX_PAYLOAD_BYTES + 16 + 64 * 1024 {
        return Err(portable::BundleError::Invalid("container size"));
    }
    let file = Arc::new(file);
    let reader = BufReader::with_capacity(256 * 1024, PosReader::new(file.clone(), 0, len));
    let verified = portable::verify_reader(reader, ring)?;
    if file.metadata()?.len() != len {
        return Err(portable::BundleError::PayloadMismatch("container changed while verifying"));
    }
    Ok((file, verified))
}

/// Byte ranges of the payload sections inside the container file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sections {
    pub mmdb_offset: u64,
    pub mmdb_len: u64,
    pub ioc_offset: u64,
    pub ioc_len: u64,
}

/// Locate the sections of the verified container open as `file`.
pub fn sections(file: &File, verified: &VerifiedBundle) -> Result<Sections> {
    let base = verified.payload_offset();
    let mut head = [0u8; 16];
    file.read_exact_at(&mut head, base).context("payload header")?;
    ensure!(&head[..8] == MAGIC, "payload magic");
    let len = u64::from_le_bytes(head[8..16].try_into().expect("8 bytes"));
    ensure!(len > 0 && len <= MAX_HEADER_BYTES, "payload header length");
    let mut json = vec![0u8; len as usize];
    file.read_exact_at(&mut json, base + 16).context("payload header")?;
    let header: Header = serde_json::from_slice(&json).context("payload header json")?;
    let mmdb_offset = base + 16 + len;
    let mmdb_len = header.mmdb_len as u64;
    let ioc_offset = mmdb_offset
        .checked_add(mmdb_len)
        .context("payload section overflow")?;
    let ioc_len = header.ioc_len as u64;
    let end = ioc_offset
        .checked_add(ioc_len)
        .context("payload section overflow")?;
    ensure!(
        end == base + verified.descriptor().payload.bytes,
        "payload sections do not cover the verified payload"
    );
    ensure!(
        file.metadata()?.len() == end,
        "container changed after verification"
    );
    Ok(Sections {
        mmdb_offset,
        mmdb_len,
        ioc_offset,
        ioc_len,
    })
}

/// The IPinfo Lite MMDB section (empty when the bundle carries no IPinfo).
pub fn read_mmdb(file: &File, sections: &Sections) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; sections.mmdb_len as usize];
    file.read_exact_at(&mut bytes, sections.mmdb_offset)
        .context("MMDB section truncated")?;
    Ok(bytes)
}

/// Streaming reader of the IOC section rows.
pub struct IocRows {
    reader: BufReader<PosReader>,
    line: Vec<u8>,
    rows: u64,
}

/// Stream the IOC section of the verified container open as `file`.
pub fn ioc_rows(file: Arc<File>, sections: &Sections) -> IocRows {
    IocRows {
        reader: BufReader::with_capacity(
            256 * 1024,
            PosReader::new(file, sections.ioc_offset, sections.ioc_offset + sections.ioc_len),
        ),
        line: Vec::with_capacity(1024),
        rows: 0,
    }
}

impl IocRows {
    /// Rows read so far.
    pub fn count(&self) -> u64 {
        self.rows
    }

    /// The next row, `None` at the end of the section.
    pub fn next_row(&mut self) -> Result<Option<IocSnapshotInput>> {
        self.line.clear();
        let n = (&mut self.reader)
            .take(MAX_IOC_ROW_BYTES as u64 + 1)
            .read_until(b'\n', &mut self.line)?;
        if n == 0 {
            return Ok(None);
        }
        ensure!(
            self.line.last() == Some(&b'\n'),
            "IOC row {} is unterminated or exceeds {MAX_IOC_ROW_BYTES} bytes",
            self.rows + 1
        );
        let body = &self.line[..self.line.len() - 1];
        let Some(tab) = body.iter().position(|b| *b == b'\t') else {
            bail!("IOC row {} has no key separator", self.rows + 1);
        };
        let row: IocSnapshotInput = serde_json::from_slice(&body[tab + 1..])
            .with_context(|| format!("IOC row {} json", self.rows + 1))?;
        ensure!(
            row.ioc_value.as_bytes() == &body[..tab],
            "IOC row {} key differs from its value",
            self.rows + 1
        );
        self.rows += 1;
        Ok(Some(row))
    }
}

#[cfg(test)]
#[path = "payload_tests.rs"]
mod tests;
