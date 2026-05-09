-- Risk Decay Configuration
-- Adds configurable TTL decay factors for risk scoring (Google SecOps-style)
--
-- Decay factors are applied based on signal age:
-- - 0-24h: decay_0_24h (default 1.0 = full weight)
-- - 1-3d:  decay_1_3d  (default 0.7)
-- - 3-5d:  decay_3_5d  (default 0.4)
-- - 5-7d:  decay_5_7d  (default 0.2)
-- - >7d:   excluded (0.0)

-- Add decay config columns to system_settings
ALTER TABLE system_settings
ADD COLUMN IF NOT EXISTS decay_0_24h NUMERIC(3,2) DEFAULT 1.0,
ADD COLUMN IF NOT EXISTS decay_1_3d NUMERIC(3,2) DEFAULT 0.7,
ADD COLUMN IF NOT EXISTS decay_3_5d NUMERIC(3,2) DEFAULT 0.4,
ADD COLUMN IF NOT EXISTS decay_5_7d NUMERIC(3,2) DEFAULT 0.2;

-- Add comments for documentation
COMMENT ON COLUMN system_settings.decay_0_24h IS 'Risk decay factor for signals 0-24 hours old (0.0-1.0, default 1.0)';
COMMENT ON COLUMN system_settings.decay_1_3d IS 'Risk decay factor for signals 1-3 days old (0.0-1.0, default 0.7)';
COMMENT ON COLUMN system_settings.decay_3_5d IS 'Risk decay factor for signals 3-5 days old (0.0-1.0, default 0.4)';
COMMENT ON COLUMN system_settings.decay_5_7d IS 'Risk decay factor for signals 5-7 days old (0.0-1.0, default 0.2)';

-- Ensure the default row has values set
UPDATE system_settings
SET
    decay_0_24h = COALESCE(decay_0_24h, 1.0),
    decay_1_3d = COALESCE(decay_1_3d, 0.7),
    decay_3_5d = COALESCE(decay_3_5d, 0.4),
    decay_5_7d = COALESCE(decay_5_7d, 0.2)
WHERE id = 'default';
