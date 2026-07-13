-- NAN-1791: retro-hunt per-rule delta state.
--
-- Two pieces of state let each run process only the NEW indicators and never
-- re-alert on one already hunted:
--
--   * retro_hunt_rule_state.(watermark, watermark_value) - a KEYSET cursor over
--     the feed ordered by (fetched_at, lower(key_value)). Each run takes the
--     next `cap` candidates strictly AFTER the cursor and advances the cursor to
--     the last one it covered, so an over-cap backlog drains across runs.
--
--     The cursor is a COMPOSITE (timestamp, value) pair, not a bare timestamp,
--     precisely because a feed sync bulk-stamps thousands of indicators with the
--     SAME fetched_at. A timestamp-only cursor cannot advance past a tie group
--     larger than `cap` without skipping its unprocessed members — and if it
--     refuses to advance, the capped query keeps returning the same already-
--     hunted rows forever and the rest of the tie group is NEVER hunted. The
--     value tiebreak makes the cursor strictly monotonic, so every run makes
--     forward progress.
--
--   * retro_hunt_hunted_indicators     - the set of indicator VALUES already
--     hunted by this rule. custom_enrichment_results is a ReplacingMergeTree
--     keyed on the indicator, so a feed re-sync refreshes fetched_at for the
--     SAME value, pushing it back above the cursor; the cursor alone would
--     re-hunt it. This anti-join set is the correctness backstop that guarantees
--     an indicator is hunted at most once per rule (paired with the
--     finding-emission dedup on re-alert).

CREATE TABLE IF NOT EXISTS retro_hunt_rule_state (
    rule_id         UUID PRIMARY KEY REFERENCES detection_rules(id) ON DELETE CASCADE,
    -- Keyset cursor: the fetched_at of the last candidate the rule covered.
    -- NULL = never run (bootstrap: the first run starts at the beginning of the
    -- live feed, capped, with the overflow carried to later runs).
    watermark       TIMESTAMPTZ,
    -- Keyset cursor tiebreak: the lowercased indicator value of that same last
    -- covered candidate. Paired with `watermark` above.
    watermark_value TEXT,
    last_run_at     TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- GROWTH: this set is intentionally NOT expired. It is the "have I ever hunted
-- this indicator for this rule" ledger, so pruning a row would let a re-synced
-- indicator be hunted (and alerted) a second time. It grows with the number of
-- DISTINCT indicators a rule has ever seen (not with log volume), and the
-- primary key is the only index needed to serve the anti-join. If a very large
-- feed ever makes this material, the follow-up is a per-rule retention policy
-- paired with a watermark floor — not a blind TTL.
CREATE TABLE IF NOT EXISTS retro_hunt_hunted_indicators (
    rule_id         UUID        NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    indicator_value TEXT        NOT NULL,
    indicator_type  TEXT        NOT NULL DEFAULT '',
    first_hunted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, indicator_value)
);
