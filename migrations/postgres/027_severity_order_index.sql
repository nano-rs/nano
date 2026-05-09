-- Migration: 027_severity_order_index
-- Description: Add expression indexes for severity sorting optimization
-- This allows ORDER BY severity to use an index instead of computing CASE for each row

-- Expression index for alerts severity sorting
-- Maps severity to integer: critical=1, high=2, medium=3, low=4, else=5
CREATE INDEX IF NOT EXISTS idx_alerts_severity_order
ON alerts ((
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END
), created_at DESC);

-- Expression index for cases severity sorting
CREATE INDEX IF NOT EXISTS idx_cases_severity_order
ON cases ((
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END
), priority DESC, created_at DESC);
