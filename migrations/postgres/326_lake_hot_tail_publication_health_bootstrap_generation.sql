-- NAN-2361 wave 8: the bootstrap generation (an empty Iceberg table, no
-- snapshot yet) is published so an empty-lake tenant can search. Its manifest
-- carries `base_snapshot_id = 0` (`BOOTSTRAP_SNAPSHOT_ID`); the staged-tail
-- heartbeat for it was rejected by `CHECK (base_snapshot_id > 0)` on the
-- publication health ledger, so the query worker never saw a matching
-- hot-tail identity and stayed `unservable` (`identity_mismatch`) on a tenant
-- that had nothing wrong with it (tenant1, 2026-09-17). Real snapshots stay
-- strictly positive; 0 is the one sentinel.

ALTER TABLE lake_hot_tail_publication_health
    DROP CONSTRAINT IF EXISTS lake_hot_tail_publication_health_base_snapshot_id_check;
ALTER TABLE lake_hot_tail_publication_health
    ADD CONSTRAINT lake_hot_tail_publication_health_base_snapshot_id_check
    CHECK (base_snapshot_id >= 0);
COMMENT ON COLUMN lake_hot_tail_publication_health.base_snapshot_id IS
    'Iceberg snapshot the signed hot tail is based on; 0 is the bootstrap generation of an empty table (NAN-2361 wave 8), every real snapshot is > 0.';
