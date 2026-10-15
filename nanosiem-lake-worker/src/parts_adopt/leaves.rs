// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded external sort of Merkle leaves (contract 4.2).
//!
//! An adopted object keeps its original layout, which is not guaranteed to
//! be `(time, metadata.uid)` order. The contract root is over leaves in that
//! order, so the leaves `(time, uid, row_digest)` are buffered up to a cap,
//! sorted, spilled as runs, and k-way merged. Memory is the buffer plus one
//! 64 KiB read buffer per run, never the object's row count.

use anyhow::{bail, Context, Result};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

/// One Merkle leaf before hashing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Leaf {
    pub time_us: i64,
    pub uid: Box<str>,
    pub digest: [u8; 32],
}

/// Sorts leaves by `(time, uid, digest)` with bounded memory.
pub struct LeafSorter {
    buffer: Vec<Leaf>,
    cap: usize,
    runs: Vec<PathBuf>,
    dir: PathBuf,
    pushed: u64,
}

impl LeafSorter {
    pub fn new(dir: &Path, cap: usize) -> Self {
        Self { buffer: Vec::new(), cap: cap.max(1), runs: Vec::new(), dir: dir.to_path_buf(), pushed: 0 }
    }

    pub fn push(&mut self, time_us: i64, uid: &str, digest: [u8; 32]) -> Result<()> {
        if uid.len() > u32::MAX as usize {
            bail!("uid exceeds the leaf bound");
        }
        self.buffer.push(Leaf { time_us, uid: uid.into(), digest });
        self.pushed += 1;
        if self.buffer.len() >= self.cap {
            self.spill()?;
        }
        Ok(())
    }

    pub fn spilled_runs(&self) -> usize {
        self.runs.len()
    }

    fn spill(&mut self) -> Result<()> {
        self.buffer.sort_unstable();
        let path = self.dir.join(format!(".leaves-run-{:05}.bin", self.runs.len()));
        let mut out = BufWriter::with_capacity(1 << 16, File::create(&path)?);
        for leaf in self.buffer.drain(..) {
            out.write_all(&leaf.time_us.to_le_bytes())?;
            out.write_all(&(leaf.uid.len() as u32).to_le_bytes())?;
            out.write_all(leaf.uid.as_bytes())?;
            out.write_all(&leaf.digest)?;
        }
        out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        self.runs.push(path);
        Ok(())
    }

    /// Emit every leaf in sorted order. Returns the count.
    pub fn finish(mut self, mut emit: impl FnMut(&Leaf) -> Result<()>) -> Result<u64> {
        if self.runs.is_empty() {
            self.buffer.sort_unstable();
            for leaf in &self.buffer {
                emit(leaf)?;
            }
            return Ok(self.pushed);
        }
        if !self.buffer.is_empty() {
            self.spill()?;
        }
        let mut readers = self
            .runs
            .iter()
            .map(|path| Ok(BufReader::with_capacity(1 << 16, File::open(path)?)))
            .collect::<Result<Vec<_>>>()?;
        let mut heap = BinaryHeap::new();
        for (index, reader) in readers.iter_mut().enumerate() {
            if let Some(leaf) = read_leaf(reader)? {
                heap.push(Reverse((leaf, index)));
            }
        }
        let mut emitted = 0_u64;
        while let Some(Reverse((leaf, index))) = heap.pop() {
            emit(&leaf)?;
            emitted += 1;
            if let Some(next) = read_leaf(&mut readers[index])? {
                if next < leaf {
                    bail!("leaf run is not sorted");
                }
                heap.push(Reverse((next, index)));
            }
        }
        drop(readers);
        for run in &self.runs {
            std::fs::remove_file(run).with_context(|| format!("remove leaf run {}", run.display()))?;
        }
        if emitted != self.pushed {
            bail!("leaf merge emitted {emitted} of {} leaves", self.pushed);
        }
        Ok(emitted)
    }
}

fn read_exact_or_eof(reader: &mut impl Read, buf: &mut [u8]) -> Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            if filled == 0 {
                return Ok(false);
            }
            bail!("leaf run is truncated");
        }
        filled += n;
    }
    Ok(true)
}

fn read_leaf(reader: &mut impl Read) -> Result<Option<Leaf>> {
    let mut head = [0_u8; 12];
    if !read_exact_or_eof(reader, &mut head)? {
        return Ok(None);
    }
    let time_us = i64::from_le_bytes(head[..8].try_into()?);
    let len = u32::from_le_bytes(head[8..].try_into()?) as usize;
    let mut uid = vec![0_u8; len];
    reader.read_exact(&mut uid)?;
    let mut digest = [0_u8; 32];
    reader.read_exact(&mut digest)?;
    let uid = String::from_utf8(uid).context("leaf uid is not UTF-8")?;
    Ok(Some(Leaf { time_us, uid: uid.into_boxed_str(), digest }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spilled_sort_equals_in_memory_sort() {
        let dir = tempfile::tempdir().unwrap();
        let mut spilled = LeafSorter::new(dir.path(), 16);
        let mut reference = Vec::new();
        for i in 0..1_000_u32 {
            let time = i64::from((i * 7_919) % 211);
            let uid = format!("u{}", (i * 31) % 997);
            let digest = [(i % 251) as u8; 32];
            spilled.push(time, &uid, digest).unwrap();
            reference.push(Leaf { time_us: time, uid: uid.into(), digest });
        }
        assert!(spilled.spilled_runs() > 50);
        reference.sort();
        let mut out = Vec::new();
        assert_eq!(spilled.finish(|leaf| { out.push(leaf.clone()); Ok(()) }).unwrap(), 1_000);
        assert_eq!(out, reference);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
