-- =============================================================================
-- 167: baseline-agg MV activation watermark (NAN-1895)
-- =============================================================================
--
-- The `| baseline` day agg (migration 166) self-enables off a coverage gate.
-- An earlier data-presence gate (`count(DISTINCT day)` over the agg) was a
-- PROXY: because `day = toDate(timestamp)`, a single late-arriving event with
-- an old timestamp — or a partial backfill — creates a lone agg row for a day
-- the MVs were NOT yet fully aggregating, so the gate passed while the day was
-- actually partial → a value seen earlier that day is absent → false-"new".
-- No data-presence check can tell a full day from a partial one.
--
-- This meta table records WHEN the baseline-agg infrastructure went live — a
-- data-INDEPENDENT watermark. The read-path gate
-- (`entity_dimension_firsts_from_agg`) serves from the agg only when a query's
-- whole lookback is at/after `active_since` (so every event of the lookback,
-- including late arrivals, flowed through a LIVE MV), or — for a lookback that
-- reaches before activation — only when the marker table
-- (`entity_dimension_day_agg_backfill_progress`) shows the pre-activation days
-- were BACKFILLED. Otherwise it falls back to the always-correct raw scan.
--
-- ONE `active_since` for BOTH lanes: the UDM + OCSF MVs from migration 166
-- activate together (same migration), so a single watermark governs both
-- `entity_dimension_day_agg` and its OCSF twin.
--
-- INSERT-ONCE: the INSERT is guarded by `WHERE (SELECT count() ...) = 0`, so
-- re-running the migrator (idempotent replays, `force-mark` recovery) never
-- resets the watermark. ReplacingMergeTree(k) additionally collapses any
-- duplicate to one row. The insert-once is NOT atomic — two concurrent
-- migrators could both see count()=0 and insert different timestamps — so the
-- READER (search/service/asset.rs) takes MAX(active_since): deterministic AND
-- conservative (the later activation trusts less of any lookback).
--
-- STAMP ORDER: this migration runs AFTER 166 (lower number applies first), so
-- 166's MVs already exist when active_since is stamped here — the watermark can
-- never predate the MVs it vouches for. (Fresh bootstrap gets the same ordering
-- from clickhouse/init.sql, where the stamp is emitted after the UDM MVs.)
--
-- ⚠ On a tenant where migration 166 was applied in an EARLIER release and 167
-- lands later, `active_since` is stamped at 167's apply time — AFTER the MVs
-- actually went live. That is CONSERVATIVE (the gate distrusts the real
-- 166→167 window until the lookback scrolls past `active_since`, falling back
-- to raw), which is safe, never wrong. On Saturn / fresh installs 166 + 167
-- deploy together, so there is no gap.
--
-- Not distributed-wrapped (matches entity_dimension_day_agg_backfill_progress):
-- a tiny single-row meta table read locally. Keep in lockstep with
-- clickhouse/init.sql (base bootstrap).

CREATE TABLE IF NOT EXISTS nanosiem.baseline_agg_meta
(
    `k` LowCardinality(String),              -- 'active_since'
    `active_since` DateTime64(6, 'UTC')
)
ENGINE = ReplacingMergeTree()
ORDER BY k;

INSERT INTO nanosiem.baseline_agg_meta (k, active_since)
SELECT 'active_since', now64(6)
WHERE (SELECT count() FROM nanosiem.baseline_agg_meta WHERE k = 'active_since') = 0;
