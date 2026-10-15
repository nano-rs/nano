WITH RECURSIVE snapshots(id, depth) AS (
    (SELECT compaction_snapshot_id, 1 FROM lake_hot_tail_objects
     WHERE tenant_id = $1 AND table_location_prefix = $2 AND status = 'compacted'
       AND compaction_snapshot_id IS NOT NULL
     ORDER BY compaction_snapshot_id LIMIT 1)
    UNION ALL
    SELECT next.id, snapshots.depth + 1 FROM snapshots
    CROSS JOIN LATERAL (
        SELECT compaction_snapshot_id AS id FROM lake_hot_tail_objects
        WHERE tenant_id = $1 AND table_location_prefix = $2 AND status = 'compacted'
          AND compaction_snapshot_id > snapshots.id
        ORDER BY compaction_snapshot_id LIMIT 1
    ) next WHERE snapshots.depth <= 100000
), uncovered AS MATERIALIZED (
    SELECT id FROM snapshots
    WHERE NOT EXISTS (SELECT 1 FROM unnest($3::bigint[]) covered(id) WHERE covered.id = snapshots.id)
), groups AS (
    SELECT COALESCE(SUM(rows), 0) AS rows, COUNT(*) AS objects, MIN(staged_at) AS oldest
    FROM lake_hot_tail_objects
    WHERE tenant_id = $1 AND table_location_prefix = $2 AND status = 'staged'
    UNION ALL
    SELECT sample.* FROM uncovered CROSS JOIN LATERAL (
        SELECT COALESCE(SUM(rows), 0) AS rows, COUNT(*) AS objects, MIN(staged_at) AS oldest
        FROM lake_hot_tail_objects
        WHERE tenant_id = $1 AND table_location_prefix = $2 AND status = 'compacted'
          AND compaction_snapshot_id = uncovered.id
    ) sample
)
SELECT SUM(rows)::bigint AS rows, SUM(objects)::bigint AS objects, MIN(oldest) AS oldest,
       (SELECT COUNT(*) > 100000 FROM snapshots) AS exceeded
FROM groups
