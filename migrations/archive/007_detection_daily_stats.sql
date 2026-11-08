-- Daily statistics for detection rules
-- Tracks match counts per day for sparkline charts and trend analysis

CREATE TABLE IF NOT EXISTS detection_daily_stats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    match_count BIGINT NOT NULL DEFAULT 0,
    alert_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- One row per rule per day
    UNIQUE(rule_id, date)
);

-- Index for efficient lookups
CREATE INDEX IF NOT EXISTS idx_detection_daily_stats_rule_date 
    ON detection_daily_stats(rule_id, date DESC);

-- Index for date range queries
CREATE INDEX IF NOT EXISTS idx_detection_daily_stats_date 
    ON detection_daily_stats(date DESC);

-- Function to upsert daily stats
CREATE OR REPLACE FUNCTION upsert_detection_daily_stats(
    p_rule_id UUID,
    p_date DATE,
    p_match_count BIGINT,
    p_alert_count BIGINT DEFAULT 0
) RETURNS void AS $$
BEGIN
    INSERT INTO detection_daily_stats (rule_id, date, match_count, alert_count)
    VALUES (p_rule_id, p_date, p_match_count, p_alert_count)
    ON CONFLICT (rule_id, date) 
    DO UPDATE SET 
        match_count = detection_daily_stats.match_count + EXCLUDED.match_count,
        alert_count = detection_daily_stats.alert_count + EXCLUDED.alert_count,
        updated_at = NOW();
END;
$$ LANGUAGE plpgsql;
