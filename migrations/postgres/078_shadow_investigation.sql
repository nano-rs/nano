-- Shadow Investigation (Auto-Triage on Case Creation)
--
-- When AI auto-investigate is enabled, the system immediately creates a notebook
-- and runs SOC-analyst-style queries, populating the notebook with entity pivots,
-- stats, and a summary before an analyst arrives.

-- a) Setting toggle
ALTER TABLE system_settings
  ADD COLUMN IF NOT EXISTS case_auto_investigate_enabled BOOLEAN DEFAULT false;

-- b) Source column on notebook_entries (analyst vs AI)
ALTER TABLE notebook_entries
  ADD COLUMN IF NOT EXISTS source TEXT DEFAULT 'analyst' NOT NULL;

-- c) System AI user (FK target for created_by on AI entries)
INSERT INTO users (id, email, name, password_hash, status)
VALUES ('00000000-0000-0000-0000-000000000099', 'system-ai@nanosiem.local', 'NanoSIEM AI', '', 'system')
ON CONFLICT (id) DO NOTHING;

-- d) Tracking table for observability
CREATE TABLE IF NOT EXISTS shadow_investigations (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  notebook_id UUID NOT NULL REFERENCES notebooks(id) ON DELETE CASCADE,
  alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
  status TEXT DEFAULT 'pending' NOT NULL CHECK (status IN ('pending','running','completed','failed','throttled')),
  queries_run INTEGER DEFAULT 0,
  entries_created INTEGER DEFAULT 0,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  error_message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_shadow_inv_case ON shadow_investigations(case_id);
CREATE INDEX IF NOT EXISTS idx_shadow_inv_status ON shadow_investigations(status) WHERE status IN ('pending','running');
