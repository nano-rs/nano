// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared bucket-drop sizing: the renderer and converter must reserve the
//! same memory for every lane before advertising its wire-byte capacity.

use crate::budget::MIB;

/// Largest admitted landed object (compressed bytes on the object store).
/// Re-exported by the worker's file admission path.
pub const MAX_LANDING_BYTES: u64 = 256 * MIB;
/// NAN-4319's production conversion heap bound: 64 MiB plus four copies of
/// the compressed input (reader, landed body, encoded bronze and transport).
pub const CONVERSION_FIXED_BYTES: u64 = 64 * MIB;
pub const CONVERSION_WIRE_COPIES: u64 = 4;
/// Runtime, clients and allocator headroom outside the per-converter bound.
pub const PROCESS_RESERVE_BYTES: u64 = 64 * MIB;
pub const LANE_MEMORY_BYTES: u64 =
    CONVERSION_FIXED_BYTES + CONVERSION_WIRE_COPIES * MAX_LANDING_BYTES;

pub const fn memory_for_lanes(lanes: usize) -> u64 {
    PROCESS_RESERVE_BYTES.saturating_add(LANE_MEMORY_BYTES.saturating_mul(lanes as u64))
}

/// A lane can always read one maximum-size admitted object. Insufficient
/// memory admits no conversion; silently running one anyway risks an OOM.
pub fn limits(memory: u64, cpu_millis: u32) -> (usize, u64) {
    let memory_lanes = memory.saturating_sub(PROCESS_RESERVE_BYTES) / LANE_MEMORY_BYTES;
    let cpu_lanes = u64::from(cpu_millis.div_ceil(1000).max(1));
    let lanes = memory_lanes.min(cpu_lanes);
    (lanes as usize, lanes * MAX_LANDING_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_boundaries_reserve_the_real_maximum_object() {
        for lanes in 1..=64 {
            let memory = memory_for_lanes(lanes);
            assert_eq!(
                limits(memory, 64_000),
                (lanes, lanes as u64 * MAX_LANDING_BYTES)
            );
            assert_eq!(limits(memory - 1, 64_000).0, lanes - 1);
            assert_eq!(limits(memory, 500), (1, MAX_LANDING_BYTES));
        }
        for memory in [
            0,
            PROCESS_RESERVE_BYTES - 1,
            PROCESS_RESERVE_BYTES,
            memory_for_lanes(1) - 1,
        ] {
            assert_eq!(limits(memory, 64_000), (0, 0));
        }
        assert_eq!(
            limits(u64::MAX, u32::MAX).0,
            u32::MAX.div_ceil(1000) as usize
        );
        assert_eq!(memory_for_lanes(usize::MAX), u64::MAX);
    }
}
