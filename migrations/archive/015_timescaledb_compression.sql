-- Enable compression on the logs hypertable
-- TimescaleDB extension is already enabled in 001_initial_schema.sql

-- Enable compression on the logs hypertable
-- segment_by: columns to keep together (improves query performance for filtered queries)
-- order_by: sort order within compressed chunks (timestamp DESC for recent-first queries)
ALTER TABLE logs SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'src_ip, dest_ip',
    timescaledb.compress_orderby = 'timestamp DESC'
);

-- Add compression policy: compress chunks older than 1 day
-- Hot data (last 24h) stays uncompressed for fast writes
-- Older data gets compressed (10-20x smaller, actually faster for analytical queries)
SELECT add_compression_policy('logs', INTERVAL '1 day', if_not_exists => true);

-- Optional: Add retention policy to automatically drop old data
-- Uncomment and adjust interval as needed:
-- SELECT add_retention_policy('logs', INTERVAL '90 days', if_not_exists => true);
