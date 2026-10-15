-- Use the same observation duration for fill and completed-batch drain.
-- A young tenant gets at least 60 seconds of denominator, never a one-second
-- extrapolation. History outside the trailing 15 minutes is not needed.
-- Count the pack frontier, retaining completed compaction inputs. Counting
-- pack-superseded ancestors or the compactor's replacement outputs would
-- count the same rows repeatedly and make the drain inflate its own fill.
-- Packed objects inherit oldest input staged_at, so this is a ledger-age
-- estimate rather than the wall-clock arrival time of each physical pack.
WITH arrivals AS (
    SELECT COUNT(*)::double precision AS objects,
           COALESCE(SUM(rows), 0)::double precision AS rows,
           COALESCE(SUM(object_bytes), 0)::double precision AS bytes,
           GREATEST(60, LEAST(900, COALESCE(EXTRACT(EPOCH FROM
               (statement_timestamp() - MIN(staged_at))), 900)))::double precision AS seconds
    FROM lake_hot_tail_objects
    WHERE tenant_id=$1 AND table_location_prefix=$2
      AND (status <> 'superseded' OR compaction_batch_id IS NOT NULL)
      AND NOT (status = 'compacted' AND compaction_batch_id IS NULL
               AND bronze_store_id = 'nano-tail-pack-v1-final')
      AND staged_at >= statement_timestamp() - INTERVAL '15 minutes'
      AND staged_at <= statement_timestamp()
)
SELECT arrivals.*,
       CASE WHEN $3 = 'pack' THEN
         (SELECT GREATEST(0, COUNT(*) - COUNT(DISTINCT superseded_by_batch_sha256))::double precision
          FROM lake_hot_tail_objects WHERE tenant_id=$1 AND table_location_prefix=$2
            AND status='superseded' AND compaction_batch_id IS NULL
            AND superseded_at >= statement_timestamp() - arrivals.seconds * INTERVAL '1 second'
            AND superseded_at <= statement_timestamp())
       ELSE (SELECT COALESCE(SUM(input_objects), 0)::double precision
        FROM lake_tail_compaction_batches
        WHERE tenant_id=$1 AND table_location_prefix=$2 AND status='completed'
          AND completed_at >= statement_timestamp() - arrivals.seconds * INTERVAL '1 second'
          AND completed_at <= statement_timestamp()) END AS drained,
       GREATEST(0, EXTRACT(EPOCH FROM (statement_timestamp() - COALESCE(
         CASE WHEN $3 = 'pack' THEN
           (SELECT MAX(superseded_at) FROM lake_hot_tail_objects
            WHERE tenant_id=$1 AND table_location_prefix=$2 AND status='superseded'
              AND compaction_batch_id IS NULL)
         ELSE (SELECT MAX(completed_at) FROM lake_tail_compaction_batches
               WHERE tenant_id=$1 AND table_location_prefix=$2 AND status='completed') END,
         (SELECT MIN(staged_at) FROM lake_hot_tail_objects
          WHERE tenant_id=$1 AND table_location_prefix=$2 AND status='staged')))))::double precision
         AS seconds_since_last_commit,
       (SELECT COUNT(*) FROM lake_hot_tail_objects
        WHERE tenant_id=$1 AND table_location_prefix=$2 AND status='staged') AS staged
FROM arrivals
