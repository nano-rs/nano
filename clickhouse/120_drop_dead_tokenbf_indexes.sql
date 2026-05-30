-- NAN-1039: drop tokenbf_v1 indexes left behind by NAN-1026 Phase 2.
--
-- Phase 2 of NAN-1026 swapped codegen from hasToken*/hasTokenCaseInsensitive
-- to iLike for all UDM-column searches. tokenbf_v1 is a probabilistic bloom
-- over alphanumeric tokens — only useful for hasToken — so these two indexes
-- have been dead weight since Phase 2 shipped. The Phase 1 migration (119)
-- explicitly flagged them with "will be retired in Phase 2."
--
-- Saturn evidence (single replica): idx_message_tokens = 2.53 GiB compressed;
-- idx_resource_name = 6.78 MiB compressed. Per-replica savings are concrete.
--
-- For resource_name we also add a splitByNonAlpha text index, matching the
-- pattern from migration 119. Without it, iLike queries on resource_name fall
-- through to a full column scan (which is what they already do today, since
-- tokenbf only ever helped hasToken — codegen no longer emits that). The new
-- index brings resource_name in line with file_path, registry_path, etc.
--
-- NAN-1052: `DROP INDEX` triggers a CH-side mutation that rewrites every
-- part to purge index files. With `alter_sync=1` (CH default) the ALTER
-- waits on that mutation synchronously, and on memory-constrained tenants
-- (org / Hetzner docker-compose, 1.8 GiB CH cap) a single large merged
-- part exceeds the per-mutation budget and OOMs. Work around this by:
--   * `mutations_sync = 0` — ALTER returns immediately; the mutation queues
--     server-side and runs in background. CH retries per-part as memory
--     allows. The migration is recorded as applied even if some parts take
--     multiple passes to drain.
--   * `max_threads = 1` — minimizes parallel buffer allocations during the
--     mutation itself, giving the biggest parts the best chance to fit.
-- Safe to interrupt and resume; ClickHouse tracks per-part progress.

ALTER TABLE nanosiem.logs DROP INDEX IF EXISTS idx_message_tokens
    SETTINGS mutations_sync = 0, max_threads = 1;

ALTER TABLE nanosiem.logs DROP INDEX IF EXISTS idx_resource_name
    SETTINGS mutations_sync = 0, max_threads = 1;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_resource_name_words
    lower(resource_name) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;

ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_resource_name_words
    SETTINGS mutations_sync = 0, max_threads = 1;
