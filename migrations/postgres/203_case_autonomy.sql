-- NAN-1251 (P4): autonomy policy + auto-close.
--
-- `case_autonomy_mode` controls how far the AI Tier-1 triage acts:
--   off            — the AI doesn't even record a recommendation.
--   recommend_only — (default) writes ai_* columns + surfaces them; never
--                    mutates human-owned status/disposition. A permanent,
--                    first-class state — teams can stay here forever.
--   auto_close     — additionally auto-closes low-risk, high-confidence FP /
--                    benign cases, behind an agreement gate. Explicit opt-in.
--
-- Auto-close gates on AGREEMENT signals, not the model's confidence alone:
-- confidence >= threshold AND severity <= ceiling AND an FP precedent exists.

ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS case_autonomy_mode TEXT;
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS case_auto_close_min_confidence NUMERIC(3, 2);
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS case_auto_close_max_severity TEXT;

COMMENT ON COLUMN system_settings.case_autonomy_mode IS
    'NAN-1251: off | recommend_only (default) | auto_close. AI Tier-1 triage autonomy level.';
COMMENT ON COLUMN system_settings.case_auto_close_min_confidence IS
    'NAN-1251: minimum AI confidence (0-1) for auto-close eligibility. Default 0.85.';
COMMENT ON COLUMN system_settings.case_auto_close_max_severity IS
    'NAN-1251: highest case severity eligible for auto-close (cases at or below this rank). Default low.';

-- Marker so AI-closed cases are distinguishable from human-closed ones in the
-- UI (filter + badge) and auditable.
ALTER TABLE cases ADD COLUMN IF NOT EXISTS ai_closed BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN cases.ai_closed IS
    'NAN-1251: true when the AI Tier-1 triage auto-closed this case (closed_by = SYSTEM_AI_USER_ID). Reset on reopen.';
