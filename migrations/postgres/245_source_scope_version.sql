-- Cross-process source-scope cache invalidation signal (NAN-1807).
--
-- The api (:3000) and search (:3002) services each run their own
-- SourceScopeResolver cache. A per-process invalidate() after admin CRUD only
-- clears the MUTATING process; the other process would lag up to its cache TTL
-- (restricted-set 30s / per-user 60s), leaving a newly-restricted source
-- briefly visible on the search path — a bounded fail-open window.
--
-- This singleton counter is bumped in the SAME transaction as every
-- registry/grant mutation. Each resolver reads it on a short throttle and drops
-- its caches when it changes, bounding cross-process propagation to a few
-- seconds. Reading it is one cheap indexed PK lookup; the table has exactly one
-- row (enforced by the singleton PK + CHECK).
CREATE TABLE IF NOT EXISTS source_scope_version (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    version   bigint  NOT NULL DEFAULT 0
);

INSERT INTO source_scope_version (singleton, version)
VALUES (true, 0)
ON CONFLICT (singleton) DO NOTHING;
