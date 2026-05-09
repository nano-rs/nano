-- Migration: Drop windowed prevalence dictionaries (NAN-364 rollback of NAN-362).
--
-- The _1d / _7d sibling dicts introduced in 107_prevalence_windowed_dicts.sql OOM at
-- dict-refresh time: the SOURCE query does `uniqMerge(...) GROUP BY entity` against the
-- full *_prevalence_agg table before the host_count < 1000 filter, materializing an
-- unbounded aggregation state. On Civo this steadily pushed ClickHouse to its memory
-- ceiling until refreshes started failing with MEMORY_LIMIT_EXCEEDED.
--
-- Rollback: keep only the 30d dicts; sub-30d windows are now served by masking the
-- 30d dict's host_count with `if(last_seen >= cutoff, host_count, 9999)` at query time
-- (see nanosiem-core/src/search/service/prevalence_join.rs). first_seen/last_seen
-- attributes on the 30d dicts are preserved — they were added in 107 and are required
-- for the window mask.

DROP DICTIONARY IF EXISTS nanosiem.hash_prevalence_dict_7d;
DROP DICTIONARY IF EXISTS nanosiem.hash_prevalence_dict_1d;
DROP DICTIONARY IF EXISTS nanosiem.domain_prevalence_dict_7d;
DROP DICTIONARY IF EXISTS nanosiem.domain_prevalence_dict_1d;
DROP DICTIONARY IF EXISTS nanosiem.ip_prevalence_dict_7d;
DROP DICTIONARY IF EXISTS nanosiem.ip_prevalence_dict_1d;
