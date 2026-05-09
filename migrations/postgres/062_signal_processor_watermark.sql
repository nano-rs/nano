-- Signal processor watermark table for tracking processed signals from ClickHouse
-- The signal processor polls ClickHouse for new signals and creates alerts in PostgreSQL

CREATE TABLE IF NOT EXISTS signal_processor_watermarks (
    id TEXT PRIMARY KEY DEFAULT 'default',
    last_inserted_at TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    last_signal_id UUID,
    processed_count BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert default watermark if not exists
INSERT INTO signal_processor_watermarks (id) VALUES ('default')
ON CONFLICT (id) DO NOTHING;
